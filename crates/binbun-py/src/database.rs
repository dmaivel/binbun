//! `binbun.open` and the [`Database`] it returns: one binary opened as a
//! `binbun-session` session in process, its entities (`db.functions`,
//! `db.xrefs`, …) and its C (`decompile`, `decompile_all`).

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread;

use binbun::Database as Engine;
use binbun::cfg::{BlockId, FunctionId};
use binbun::strings::Literal;
use binbun_loader::{Format, Machine};
use binbun_print::style::{IntSpelling, Naming, Spacing, Style};
use binbun_protocol::messages::method;
use binbun_protocol::server::members;
use binbun_protocol::{Host, Owner, Write, stage_number, talk};
use binbun_session::signatures::Options as SignatureOptions;
use binbun_session::{
    DebugSource, Document, Download, Lineage, Options, Placement, Revision as SessionRevision,
    Session, Stage, Symbols, View, Waited,
};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyInt, PyTuple};
use pyo3::{Borrowed, FromPyObject};

use crate::aarch64::Instruction as Aarch64Instruction;
use crate::disasm::Invalid;
use crate::document::{CDocument, CLine, CToken, DecompileAll};
use crate::errors::{Raise, fault, member};
use crate::events::Events;
use crate::facts::Verification;
use crate::functions::{Block, Function, Functions};
use crate::generic::Instruction as GenericInstruction;
use crate::image::{
    Bookmarks, Bytes, Comments, Entries, EntryInfo, ImportInfo, Imports, Names, Section, Sections,
    Segment, Segments, StringItem, Strings, TextHit,
};
use crate::listing::{Listing, ListingLine};
use crate::remote::{Connection, Link, Server, follow_with, from_python, to_python};
use crate::signatures::Signatures;
use crate::wait::wait_for;
use crate::writes::{self, Corrections, HistoryEntry, Transaction, Types, owner, script};
use crate::x86::Instruction as X86Instruction;
use crate::xrefs::{Xref, Xrefs};

/// An address: an `int` in `0..2**64` (another `int` is a `ValueError`),
/// or a binbun object at exactly one address ([`address_of`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Address(pub(crate) u64);

impl<'a, 'py> FromPyObject<'a, 'py> for Address {
    type Error = PyErr;

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        let address = address_of(&obj)?;
        touch(address);
        Ok(Self(address))
    }
}

/// The one address `obj` is at: an `int` in `0..2**64`; a `Function`'s
/// entry; the `address` of a `StringItem`, `TextHit`, `EntryInfo`,
/// `ImportInfo`, `ListingLine`, an instruction (`Instruction`, `Invalid`,
/// the decoders') or one of `binbun._results`' records (`Named`, …); the
/// `start` of a `Segment`, `Section` or `Block`.
///
/// # Errors
///
/// `ValueError` for an `int` out of range; `TypeError` for anything else,
/// naming the attribute to give for an object at several addresses
/// (`Xref`, `CLine`, `CToken`, `Verification`).
pub(crate) fn address_of(obj: &Bound<'_, PyAny>) -> PyResult<u64> {
    if obj.is_instance_of::<PyInt>() {
        return obj.extract::<u64>().map_err(|_| {
            PyValueError::new_err(format!("{obj} is not an address (an int in 0..2**64)"))
        });
    }
    if let Some(address) = one_address(obj) {
        return Ok(address);
    }
    let several = if obj.is_instance_of::<Xref>() {
        Some("an Xref has two addresses: give x.from_ea or x.to_ea")
    } else if obj.is_instance_of::<CLine>() {
        Some("a CLine is made from several instructions: give line.addresses[0]")
    } else if obj.is_instance_of::<CToken>() {
        Some("a CToken is made from several instructions: give token.addresses[0]")
    } else if obj.is_instance_of::<Verification>() {
        Some("a Verification is of a function: give v.function")
    } else {
        None
    };
    Err(PyTypeError::new_err(several.map_or_else(
        || {
            let name = obj
                .get_type()
                .name()
                .map_or_else(|_| "?".to_owned(), |name| name.to_string());
            format!("an address is an int or a binbun object at one address, not {name}")
        },
        str::to_owned,
    )))
}

/// The one address of a binbun object at one, if `obj` is one.
fn one_address(obj: &Bound<'_, PyAny>) -> Option<u64> {
    if let Ok(function) = obj.cast::<Function>() {
        return Some(function.get().entry);
    }
    macro_rules! field {
        ($($class:ty => $field:ident),* $(,)?) => {
            $(if let Ok(item) = obj.cast::<$class>() {
                return Some(item.get().$field);
            })*
        };
    }
    field!(
        StringItem => address,
        TextHit => address,
        EntryInfo => address,
        ImportInfo => address,
        ListingLine => address,
        GenericInstruction => address,
        Invalid => address,
        X86Instruction => address,
        Aarch64Instruction => address,
        Segment => start,
        Section => start,
        Block => start,
    );
    let module = obj.get_type().module().ok()?;
    if module.to_str().ok()? != "binbun._results" {
        return None;
    }
    obj.getattr("address").ok()?.extract::<u64>().ok()
}

/// No address touched since last asked ([`TOUCHED`]).
const UNTOUCHED: u64 = u64::MAX;

/// The one address `obj` is at, as every `ea` parameter takes it
/// ([`address_of`]): what `binbun._talk` and `binbun._remote` read
/// addresses with.
#[pyfunction]
pub(crate) fn _address(obj: &Bound<'_, PyAny>) -> PyResult<u64> {
    address_of(obj)
}

/// The address the process's Python code last named or worked on (an
/// address or function handed to the API, a function handle used):
/// where an agent's code works, its cursor in the GUI
/// (`binbun.console --agent`); [`UNTOUCHED`] if none since last asked.
static TOUCHED: AtomicU64 = AtomicU64::new(UNTOUCHED);

/// Notes that Python code works at `address` now.
pub(crate) fn touch(address: u64) {
    TOUCHED.store(address, Ordering::Relaxed);
}

/// The address Python code last named or worked on since the last call,
/// if any (an agent's presence: where its code works).
#[pyfunction]
pub(crate) fn _touched() -> Option<u64> {
    let address = TOUCHED.swap(UNTOUCHED, Ordering::Relaxed);
    (address != UNTOUCHED).then_some(address)
}

/// A function as an argument: a [`Function`] or its entry (an `int`;
/// anything else is a `TypeError`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Entry(pub(crate) u64);

impl<'a, 'py> FromPyObject<'a, 'py> for Entry {
    type Error = PyErr;

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(function) = obj.cast::<Function>() {
            let entry = function.get().entry;
            touch(entry);
            return Ok(Self(entry));
        }
        if !obj.is_instance_of::<PyInt>() {
            let name = obj
                .get_type()
                .name()
                .map_or_else(|_| "?".to_owned(), |name| name.to_string());
            return Err(PyTypeError::new_err(format!(
                "a function is a Function or its entry (an int), not {name}"
            )));
        }
        obj.extract::<Address>().map(|Address(entry)| Self(entry))
    }
}

/// The functions holding each block, of one analysis.
type Holders = HashMap<BlockId, Vec<FunctionId>>;

/// What is kept for one analysis: its number and the value.
type Kept<T> = Mutex<Option<(u64, Arc<T>)>>;

/// What every handle of one opened binary shares: its sessions (the one
/// in use and one analysing anew, written through a [`Host`]; until
/// closed) and what is indexed once per analysis.
#[derive(Debug)]
pub(crate) struct Db {
    host: RwLock<Option<Arc<Host>>>,
    /// The connection whose server this database follows (`mode="local"`):
    /// its writes are made there.
    link: RwLock<Option<Arc<Link>>>,
    /// The binary's path.
    pub(crate) path: PathBuf,
    /// The view documents are asked in without one.
    pub(crate) view: View,
    /// Whether nothing is saved.
    ephemeral: bool,
    /// The functions holding each block, of the analysis numbered.
    holders: Kept<Holders>,
    /// The string literals (at least 4 characters scanned) by address, of
    /// the analysis numbered.
    strings: Kept<BTreeMap<u64, Literal>>,
    /// The writes recorded for a suggestion instead of made, by the
    /// thread recording them ([`writes::record`]).
    pub(crate) recording: Mutex<HashMap<Owner, Vec<Write>>>,
}

impl Db {
    /// The host writes go through.
    ///
    /// # Errors
    ///
    /// The database is closed.
    pub(crate) fn host(&self, py: Python<'_>) -> PyResult<Arc<Host>> {
        self.host
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| Raise::Binbun.err(py, "the database is closed"))
    }

    /// The session in use (a new analysis whose functions are recovered
    /// swapped in first).
    ///
    /// # Errors
    ///
    /// The database is closed.
    pub(crate) fn session(&self, py: Python<'_>) -> PyResult<Arc<Session>> {
        Ok(self.host(py)?.session())
    }

    /// The connection whose server this database follows, if one is.
    pub(crate) fn link(&self) -> Option<Arc<Link>> {
        self.link
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Follows `link`'s server from now on.
    pub(crate) fn follow(&self, link: Arc<Link>) {
        *self.link.write().unwrap_or_else(PoisonError::into_inner) = Some(link);
    }

    /// The session once its functions are recovered, waiting for them.
    ///
    /// # Errors
    ///
    /// Closed; the analysis stopped before ([`Raise::NotAnalysed`]);
    /// Ctrl-C.
    pub(crate) fn analysed(&self, py: Python<'_>) -> PyResult<Arc<Session>> {
        let session = self.session(py)?;
        if session.database().is_none() {
            wait_stage(py, &session, Stage::Analysed, None)?;
        }
        Ok(session)
    }

    /// The function starting at `entry`.
    pub(crate) fn function_id(session: &Session, entry: u64) -> Option<FunctionId> {
        session.database()?.function_at(entry)
    }

    /// The functions holding each block of `session`'s `database`,
    /// indexed once per analysis.
    pub(crate) fn holders(&self, session: &Session, database: &Engine<'_>) -> Arc<Holders> {
        cached(&self.holders, session, || {
            let mut holders: Holders = HashMap::new();
            for (id, function) in database.functions() {
                for &block in &function.blocks {
                    holders.entry(block).or_default().push(id);
                }
            }
            holders
        })
    }

    /// The string literals of at least 4 characters of `session`'s
    /// `database` by address, found once per analysis.
    pub(crate) fn strings(
        &self,
        session: &Session,
        database: &Engine<'_>,
    ) -> Arc<BTreeMap<u64, Literal>> {
        cached(&self.strings, session, || {
            database
                .strings(4)
                .into_iter()
                .map(|literal| (literal.address, literal))
                .collect()
        })
    }
}

/// What `slot` keeps for `session`'s analysis, made by `make` if it keeps
/// another's or none.
fn cached<T>(slot: &Kept<T>, session: &Session, make: impl FnOnce() -> T) -> Arc<T> {
    let analysis = session.revision().analysis;
    let mut kept = slot.lock().unwrap_or_else(PoisonError::into_inner);
    match &*kept {
        Some((at, value)) if *at == analysis => Arc::clone(value),
        Some(_) | None => {
            let value = Arc::new(make());
            *kept = Some((analysis, Arc::clone(&value)));
            value
        }
    }
}

/// Waits for `stage` of `session` (Ctrl-C cancels nothing: the analysis
/// goes on for the next wait).
///
/// # Errors
///
/// The analysis stopped before ([`Raise::NotAnalysed`], or
/// [`Raise::Open`] if opening failed); the timeout; Ctrl-C.
pub(crate) fn wait_stage(
    py: Python<'_>,
    session: &Arc<Session>,
    stage: Stage,
    timeout: Option<f64>,
) -> PyResult<Stage> {
    let waited = wait_for(
        py,
        timeout,
        "waiting for the analysis",
        |slice| match session.wait(stage, Some(slice)) {
            Waited::TimedOut(_) => None,
            done @ (Waited::Reached(_) | Waited::Stopped { .. }) => Some(done),
        },
        || {},
    )?;
    match waited {
        Waited::Reached(reached) => Ok(reached),
        Waited::Stopped {
            failure: Some(failure),
            stage: Stage::Opening | Stage::Image,
        } => Err(Raise::Open.err(py, failure)),
        Waited::Stopped { stage: at, failure } => Err(Raise::NotAnalysed.err(
            py,
            format!(
                "the analysis stopped at {at:?} before {stage:?}{}",
                failure.map(|f| format!(": {f}")).unwrap_or_default()
            ),
        )),
        Waited::TimedOut(at) => Err(Raise::Timeout.err(py, format!("still at {at:?}"))),
    }
}

/// The stage `binbun.Stage`'s value `number` is.
pub(crate) fn stage_of(number: u8) -> PyResult<Stage> {
    const STAGES: [Stage; 7] = [
        Stage::Opening,
        Stage::Image,
        Stage::Analysed,
        Stage::Referenced,
        Stage::Signatures,
        Stage::Callers,
        Stage::Warmed,
    ];
    STAGES
        .get(usize::from(number))
        .copied()
        .ok_or_else(|| PyValueError::new_err(format!("no stage {number}")))
}

/// `stage` as a `binbun.Stage`.
pub(crate) fn stage_object(py: Python<'_>, stage: Stage) -> PyResult<Bound<'_, PyAny>> {
    member(py, "Stage", stage_number(stage))
}

/// The view `view` (a `binbun.View` or its value) names; `default` for
/// `None`.
///
/// # Errors
///
/// It names no view.
pub(crate) fn view_of(view: Option<&Bound<'_, PyAny>>, default: View) -> PyResult<View> {
    let Some(view) = view.filter(|view| !view.is_none()) else {
        return Ok(default);
    };
    let value = match view.getattr("value") {
        Ok(value) => value,
        Err(_) => view.clone(),
    };
    match value.extract::<String>()?.as_str() {
        "exact" => Ok(View::Exact),
        "reading" => Ok(View::Reading),
        other => Err(PyValueError::new_err(format!(
            "no view {other:?} (exact, reading)"
        ))),
    }
}

/// How `types` (`"fixed"` or `"plain"`) has the C spell integer types.
///
/// # Errors
///
/// Another value.
fn spelling_of(types: &str) -> PyResult<IntSpelling> {
    match types {
        "fixed" => Ok(IntSpelling::Fixed),
        "plain" => Ok(IntSpelling::Plain),
        other => Err(PyValueError::new_err(format!(
            "types={other:?}: fixed or plain"
        ))),
    }
}

/// `declarations=`: `"scoped"` or `"top"`.
fn placement_of(declarations: &str) -> PyResult<Placement> {
    match declarations {
        "scoped" => Ok(Placement::Scoped),
        "top" => Ok(Placement::Top),
        other => Err(PyValueError::new_err(format!(
            "declarations={other:?}: scoped or top"
        ))),
    }
}

/// `names=`: `"numbered"` or `"registers"`.
fn naming_of(names: &str) -> PyResult<Naming> {
    match names {
        "numbered" => Ok(Naming::Numbered),
        "registers" => Ok(Naming::Registers),
        other => Err(PyValueError::new_err(format!(
            "names={other:?}: numbered or registers"
        ))),
    }
}

/// `spacing=`: `"paragraphs"` or `"compact"`.
fn spacing_of(spacing: &str) -> PyResult<Spacing> {
    match spacing {
        "paragraphs" => Ok(Spacing::Paragraphs),
        "compact" => Ok(Spacing::Compact),
        other => Err(PyValueError::new_err(format!(
            "spacing={other:?}: paragraphs or compact"
        ))),
    }
}

/// `view` as a `binbun.View`.
pub(crate) fn view_object(py: Python<'_>, view: View) -> PyResult<Bound<'_, PyAny>> {
    let value = match view {
        View::Exact => "exact",
        View::Reading => "reading",
    };
    member(py, "View", value)
}

/// A session's revision as a [`Revision`].
pub(crate) fn revision(revision: SessionRevision) -> Revision {
    Revision {
        analysis: revision.analysis,
        edits: revision.edits,
    }
}

/// How far a database's state has come: analyses swapped in (corrections,
/// debug information fetched) and edits made. Every document carries the
/// revision it was printed at.
#[pyclass(frozen, eq, hash, module = "binbun._native")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Revision {
    /// Analyses before this one.
    #[pyo3(get)]
    pub(crate) analysis: u64,
    /// Edits made.
    #[pyo3(get)]
    pub(crate) edits: u64,
}

#[pymethods]
impl Revision {
    fn __repr__(&self) -> String {
        format!("Revision(analysis={}, edits={})", self.analysis, self.edits)
    }
}

/// How `open`'s `signatures` (`True` or `None`, `"exact"`, `False`) says
/// library functions are named.
fn signatures_of(signatures: Option<&Bound<'_, PyAny>>) -> PyResult<SignatureOptions> {
    let mut options = SignatureOptions::default();
    let Some(value) = signatures.filter(|value| !value.is_none()) else {
        return Ok(options);
    };
    if value.is_instance_of::<PyBool>() {
        options.enabled = value.extract()?;
    } else if value.extract::<String>().ok().as_deref() == Some("exact") {
        options.behaviour = false;
    } else {
        return Err(PyValueError::new_err(format!(
            "signatures={value}: True, False or \"exact\""
        )));
    }
    Ok(options)
}

/// Opens the binary at `path` (see [`Database`]). Returns once the analysis
/// reached `wait` (by default `Stage.ANALYSED`; `None`: at once). Of a
/// universal Mach-O file, the slice `slice` (`x86_64`, `arm64e`; `None`:
/// this machine's instruction set's, else the first), as the CLI's
/// `--arch`. `signatures`: library functions named by the signature
/// packs binbun reads (`True`: by identity at `Stage.SIGNATURES`, then by
/// behaviour in the background; `"exact"`: by identity alone; `False`:
/// none). `types`: how the C spells integer types (`"fixed"`: `int32_t`;
/// `"plain"`: `int`, `long`, as C programmers write them for the
/// binary's platform). `declarations`: where the C declares locals
/// (`"scoped"`: in the blocks using them; `"top"`: all at the top of
/// each function). `names`: how the C names variables with no name of
/// their own (`"numbered"`: `a1`, `v7`; `"registers"`: by where the
/// machine code kept them, `arg1`, `rax`, `var_58`). The layout (braces,
/// indentation) is `Database.set_style`'s.
#[expect(clippy::too_many_arguments, reason = "open's keyword arguments")]
#[pyfunction]
#[pyo3(signature = (path, *, project = None, debug = None, symbols = "never", view = None, types = "fixed", declarations = "scoped", names = "numbered", warm = false, wait = Some(2), timeout = None, slice = None, signatures = None))]
pub(crate) fn open(
    py: Python<'_>,
    path: PathBuf,
    project: Option<&Bound<'_, PyAny>>,
    debug: Option<&Bound<'_, PyAny>>,
    symbols: &str,
    view: Option<&Bound<'_, PyAny>>,
    types: &str,
    declarations: &str,
    names: &str,
    warm: bool,
    wait: Option<u8>,
    timeout: Option<f64>,
    slice: Option<String>,
    signatures: Option<&Bound<'_, PyAny>>,
) -> PyResult<Database> {
    let view = view_of(view, View::Exact)?;
    let mut options = Options {
        types: spelling_of(types)?,
        declarations: placement_of(declarations)?,
        names: naming_of(names)?,
        warm,
        view,
        arch: slice,
        signatures: signatures_of(signatures)?,
        ..Options::default()
    };
    match project {
        None => {}
        Some(project) if project.is_none() => {}
        Some(project) if project.is_instance_of::<PyBool>() => {
            if project.extract::<bool>()? {
                return Err(PyValueError::new_err(
                    "project=True: give a directory, None (binbun's own) or False (none)",
                ));
            }
            options.ephemeral = true;
        }
        Some(project) => options.project = Some(project.extract::<PathBuf>()?),
    }
    options.debug = match debug {
        None => DebugSource::Search,
        Some(debug) if debug.is_none() => DebugSource::Search,
        Some(debug) => match debug.extract::<String>().ok().as_deref() {
            Some("search") => DebugSource::Search,
            Some("none") => DebugSource::Without,
            _ => DebugSource::Path(debug.extract::<PathBuf>()?),
        },
    };
    options.symbols = Symbols {
        download: match symbols {
            "never" => Download::Never,
            "ask" => Download::Ask,
            "always" => Download::Always,
            _ => {
                return Err(PyValueError::new_err(format!(
                    "symbols={symbols:?}: never, ask or always"
                )));
            }
        },
        ..Symbols::default()
    };
    let wait = wait.map(stage_of).transpose()?;
    let ephemeral = options.ephemeral;
    let lineage = Lineage::open(path.clone(), options)
        .map_err(|error| Raise::Open.err(py, error.to_string()))?;
    let host = Arc::new(Host::new(Arc::new(lineage), true));
    if let Some(stage) = wait {
        wait_stage(py, &host.session(), stage, timeout)?;
    }
    Ok(Database {
        db: Arc::new(Db {
            host: RwLock::new(Some(host)),
            link: RwLock::new(None),
            path,
            view,
            ephemeral,
            holders: Mutex::new(None),
            strings: Mutex::new(None),
            recording: Mutex::new(HashMap::new()),
        }),
    })
}

/// One binary opened (`binbun.open(path)`): analysed on threads of its
/// own, its edits in its project (binbun's own, keyed by the file's
/// SHA-256; a directory given; or none, `project=False`). Usable from
/// several Python threads; heavy calls release the GIL. A context
/// manager: `with binbun.open(path) as db:` closes it at the end.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Database {
    pub(crate) db: Arc<Db>,
}

#[pymethods]
impl Database {
    /// `binbun.open`, also reachable as `Database.open`.
    #[expect(clippy::too_many_arguments, reason = "open's keyword arguments")]
    #[staticmethod]
    #[pyo3(name = "open", signature = (path, *, project = None, debug = None, symbols = "never", view = None, types = "fixed", declarations = "scoped", names = "numbered", warm = false, wait = Some(2), timeout = None, slice = None, signatures = None))]
    fn open_static(
        py: Python<'_>,
        path: PathBuf,
        project: Option<&Bound<'_, PyAny>>,
        debug: Option<&Bound<'_, PyAny>>,
        symbols: &str,
        view: Option<&Bound<'_, PyAny>>,
        types: &str,
        declarations: &str,
        names: &str,
        warm: bool,
        wait: Option<u8>,
        timeout: Option<f64>,
        slice: Option<String>,
        signatures: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        open(
            py,
            path,
            project,
            debug,
            symbols,
            view,
            types,
            declarations,
            names,
            warm,
            wait,
            timeout,
            slice,
            signatures,
        )
    }

    /// Changes how the C is printed from now on: `braces`, the layout as
    /// `binbun decompile --style` names it (`"kr"`, the default: Kernighan
    /// and Ritchie, four spaces, braces only where needed; `"llvm"`:
    /// attached braces, two spaces; `"linux"`: tabs; `"allman"`: every
    /// brace on a line of its own, always braces); `types`, how it spells
    /// integer types (`"fixed"`: `int32_t`; `"plain"`: `int`, `long`, as
    /// C programmers write them for the binary's platform);
    /// `declarations`, where it declares locals (`"scoped"`: in the blocks
    /// using them; `"top"`: all at the top of each function); `names`, how
    /// it names variables with no name of their own (`"numbered"`: `a1`,
    /// `v7`; `"registers"`: by where the machine code kept them, `arg1`,
    /// `rax`, `var_58`); `spacing`, whether empty lines part a block's
    /// statements (`"paragraphs"`: after declarations, after a compound
    /// statement and before a label; `"compact"`: none); `None` keeps
    /// each. Documents already made keep their text; the next ones are
    /// printed again.
    #[pyo3(
        signature = (*, braces = None, types = None, declarations = None, names = None, spacing = None)
    )]
    fn set_style(
        &self,
        py: Python<'_>,
        braces: Option<&str>,
        types: Option<&str>,
        declarations: Option<&str>,
        names: Option<&str>,
        spacing: Option<&str>,
    ) -> PyResult<()> {
        let session = self.db.session(py)?;
        let mut style = session.style();
        if let Some(braces) = braces {
            let mut preset = Style::preset(braces).ok_or_else(|| {
                PyValueError::new_err(format!("braces={braces:?}: kr, llvm, linux or allman"))
            })?;
            preset.int_spelling = style.int_spelling;
            preset.declarations = style.declarations;
            preset.naming = style.naming;
            preset.hex_threshold = style.hex_threshold;
            preset.spacing = style.spacing;
            style = preset;
        }
        if let Some(types) = types {
            style = style.with_int_spelling(spelling_of(types)?);
        }
        if let Some(declarations) = declarations {
            style = style.with_declarations(placement_of(declarations)?);
        }
        if let Some(names) = names {
            style = style.with_naming(naming_of(names)?);
        }
        if let Some(spacing) = spacing {
            style = style.with_spacing(spacing_of(spacing)?);
        }
        session.set_style(style);
        Ok(())
    }

    /// Closes the database: its threads stop; every handle of it raises
    /// afterwards; a transaction open is rolled back. `save`: write the
    /// edits to the project (`None`: as opened, each change saved as
    /// made).
    #[pyo3(signature = (*, save = None))]
    fn close(&self, py: Python<'_>, save: Option<bool>) -> PyResult<()> {
        let link = self
            .db
            .link
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let finished = link.map_or(Ok(()), |link| link.close(py, true));
        let taken = self
            .db
            .host
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(host) = taken else {
            return finished;
        };
        if let Some(owner) = host.holder() {
            host.abandon(owner);
        }
        if save == Some(true) && !self.db.ephemeral {
            host.session()
                .save()
                .map_err(|error| Raise::Project.err(py, error.to_string()))?;
        }
        match Arc::try_unwrap(host) {
            Ok(host) => py.detach(|| host.close()),
            Err(shared) => shared.session().cancel(),
        }
        finished
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (*_exc))]
    fn __exit__(&self, py: Python<'_>, _exc: &Bound<'_, PyTuple>) -> PyResult<()> {
        self.close(py, None)
    }

    fn __repr__(&self) -> String {
        format!("<binbun.Database {}>", self.db.path.display())
    }

    /// The binary's path.
    #[getter]
    fn path(&self) -> String {
        self.db.path.display().to_string()
    }

    /// The binary's file name.
    #[getter]
    fn name(&self) -> String {
        self.db.path.file_name().map_or_else(
            || self.db.path.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        )
    }

    /// The SHA-256 of the file, in hexadecimal (once the image is parsed).
    #[getter]
    fn sha256(&self, py: Python<'_>) -> PyResult<Option<String>> {
        Ok(self.db.session(py)?.key().map(binbun_session::Key::hex))
    }

    /// The slice open of a universal Mach-O file (`x86_64`, `arm64e`), or
    /// `None` for any other file (once the image is parsed).
    #[getter]
    fn slice(&self, py: Python<'_>) -> PyResult<Option<String>> {
        Ok(self.db.session(py)?.slice().map(str::to_owned))
    }

    /// `Format.ELF`, `Format.PE` or `Format.MACHO`.
    #[getter]
    fn format<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let session = self.db.analysed(py)?;
        let image = session
            .image()
            .ok_or_else(|| Raise::NotAnalysed.err(py, "no image"))?;
        let format = match image.format {
            Format::Elf => "elf",
            Format::Pe => "pe",
            Format::MachO => "macho",
        };
        member(py, "Format", format)
    }

    /// The instruction set: a `Machine`.
    #[getter]
    fn machine<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        member(py, "Machine", self.architecture(py)?)
    }

    /// The instruction set's name: `x86`, `x86_64`, `aarch64`, `arm` or
    /// `other`.
    #[getter]
    fn architecture(&self, py: Python<'_>) -> PyResult<&'static str> {
        let session = self.db.analysed(py)?;
        Ok(session
            .image()
            .map_or("other", |image| match image.machine {
                Machine::X86 => "x86",
                Machine::X86_64 => "x86_64",
                Machine::Aarch64 => "aarch64",
                Machine::Arm => "arm",
                Machine::Other => "other",
            }))
    }

    /// 32 or 64.
    #[getter]
    fn bitness(&self, py: Python<'_>) -> PyResult<u32> {
        let session = self.db.analysed(py)?;
        Ok(session.image().map_or(64, |image| match image.machine {
            Machine::X86 | Machine::Arm => 32,
            Machine::X86_64 | Machine::Aarch64 | Machine::Other => 64,
        }))
    }

    /// The image's base address.
    #[getter]
    fn base_address(&self, py: Python<'_>) -> PyResult<u64> {
        let session = self.db.analysed(py)?;
        Ok(session.image().map_or(0, |image| image.base))
    }

    /// The entry point, if the image has one.
    #[getter]
    fn start_ip(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        let session = self.db.analysed(py)?;
        Ok(session.image().and_then(|image| image.entry))
    }

    /// The lowest mapped address.
    #[getter]
    fn minimum_ea(&self, py: Python<'_>) -> PyResult<u64> {
        let session = self.db.analysed(py)?;
        Ok(session
            .image()
            .and_then(|image| image.segments.iter().map(|s| s.start).min())
            .unwrap_or(0))
    }

    /// The address after the highest mapped byte.
    #[getter]
    fn maximum_ea(&self, py: Python<'_>) -> PyResult<u64> {
        let session = self.db.analysed(py)?;
        Ok(session
            .image()
            .and_then(|image| image.segments.iter().map(binbun_loader::Segment::end).max())
            .unwrap_or(0))
    }

    /// The file the debug information was read from, if any.
    #[getter]
    fn debug_file(&self, py: Python<'_>) -> PyResult<Option<String>> {
        Ok(self
            .db
            .analysed(py)?
            .debug_file()
            .map(|file| file.display().to_string()))
    }

    /// The project's directory (`None` with `project=False`).
    #[getter]
    fn project_dir(&self, py: Python<'_>) -> PyResult<Option<String>> {
        Ok(self
            .db
            .session(py)?
            .project()
            .map(|project| project.dir().display().to_string()))
    }

    /// Whether this database follows a GUI's (`binbun.connect(mode="local")`).
    #[getter]
    fn connected(&self) -> bool {
        self.db.link().is_some()
    }

    /// How far the analysis is: a `Stage`.
    #[getter]
    fn stage<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        stage_object(py, self.db.session(py)?.stage())
    }

    /// The revision now.
    #[getter]
    fn revision(&self, py: Python<'_>) -> PyResult<Revision> {
        Ok(revision(self.db.session(py)?.revision()))
    }

    /// The project files the analysis in use wrote so far (a test's count
    /// of saves; not part of the API).
    #[getter(_saves)]
    fn saves(&self, py: Python<'_>) -> PyResult<u64> {
        Ok(self.db.session(py)?.saves())
    }

    /// Waits until the analysis reaches `stage` (default `Stage.CALLERS`;
    /// without warming, `Stage.WARMED` is `Stage.CALLERS`); the stage
    /// reached. Ctrl-C stops waiting.
    #[pyo3(signature = (stage = None, *, timeout = None))]
    fn wait<'py>(
        &self,
        py: Python<'py>,
        stage: Option<u8>,
        timeout: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let stage = stage.map_or(Ok(Stage::Callers), stage_of)?;
        let session = self.db.session(py)?;
        let reached = wait_stage(py, &session, stage, timeout)?;
        stage_object(py, reached)
    }

    /// Stops the analysis and every question being answered.
    fn cancel(&self, py: Python<'_>) -> PyResult<()> {
        self.db.session(py)?.cancel();
        Ok(())
    }

    /// The functions.
    #[getter]
    fn functions(&self) -> Functions {
        Functions::new(&self.db)
    }

    /// The cross-references.
    #[getter]
    fn xrefs(&self) -> Xrefs {
        Xrefs::new(&self.db)
    }

    /// The names.
    #[getter]
    fn names(&self) -> Names {
        Names::new(&self.db)
    }

    /// The user's comments.
    #[getter]
    fn comments(&self) -> Comments {
        Comments::new(&self.db)
    }

    /// The user's bookmarks.
    #[getter]
    fn bookmarks(&self) -> Bookmarks {
        Bookmarks::new(&self.db)
    }

    /// The bytes.
    #[getter]
    fn bytes(&self) -> Bytes {
        Bytes::new(&self.db)
    }

    /// The segments.
    #[getter]
    fn segments(&self) -> Segments {
        Segments::new(&self.db)
    }

    /// The sections.
    #[getter]
    fn sections(&self) -> Sections {
        Sections::new(&self.db)
    }

    /// The string literals.
    #[getter]
    fn strings(&self) -> Strings {
        Strings::new(&self.db)
    }

    /// The entry points and exports.
    #[getter]
    fn entries(&self) -> Entries {
        Entries::new(&self.db)
    }

    /// The imports.
    #[getter]
    fn imports(&self) -> Imports {
        Imports::new(&self.db)
    }

    /// The listing.
    #[getter]
    fn listing(&self) -> Listing {
        Listing::new(&self.db)
    }

    /// The session's events.
    #[getter]
    fn events(&self) -> Events {
        Events::new(&self.db)
    }

    /// The user's types.
    #[getter]
    fn types(&self) -> Types {
        Types::new(&self.db)
    }

    /// The user's corrections of recovery.
    #[getter]
    fn corrections(&self) -> Corrections {
        Corrections::new(&self.db)
    }

    /// The library signatures: the packs, the matches, rejecting one.
    #[getter]
    fn signatures(&self) -> Signatures {
        Signatures::new(&self.db)
    }

    /// The identity key (hexadecimal) this database's changes are signed
    /// by; connected, the server's (whose session makes them).
    #[getter]
    fn identity(&self, py: Python<'_>) -> PyResult<String> {
        if let Some(identity) = self.db.link().and_then(|link| link.identity()) {
            return Ok(identity);
        }
        Ok(self.db.session(py)?.identity().to_string())
    }

    /// Calls conversation method `method` (`threads.*`, `suggestions.*`,
    /// `session.members`) with `params` (JSON-able): answered here, or
    /// connected by the server; its result. What `binbun._talk` calls.
    #[pyo3(signature = (method, params = None))]
    fn _talk(
        &self,
        py: Python<'_>,
        method: &str,
        params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        if !method.starts_with("threads.")
            && !method.starts_with("suggestions.")
            && method != method::MEMBERS
        {
            return Err(Raise::Protocol.err(py, format!("no method {method:?}")));
        }
        let params = from_python(py, params)?;
        let value = if let Some(link) = self.db.link() {
            link.call(py, method, params)?
        } else if method == method::MEMBERS {
            let session = self.db.session(py)?;
            serde_json::to_value(members(&session, Vec::new(), &[]))
                .map_err(|error| Raise::Protocol.err(py, error.to_string()))?
        } else {
            let host = self.db.host(py)?;
            let (owner, origin) = (owner(), script(py));
            py.detach(|| talk::answer(&host, owner, &origin, None, method, params))
                .map_err(|f| fault(py, f))?
        };
        to_python(py, &value)
    }

    /// The threads (`binbun._talk.Threads`).
    #[getter]
    fn threads(slf: &Bound<'_, Self>) -> PyResult<Py<PyAny>> {
        talking(slf, "Threads")
    }

    /// The suggestions (`binbun._talk.Suggestions`).
    #[getter]
    fn suggestions(slf: &Bound<'_, Self>) -> PyResult<Py<PyAny>> {
        talking(slf, "Suggestions")
    }

    /// The session: who is in it (`binbun._talk.Session`).
    #[getter]
    fn session(slf: &Bound<'_, Self>) -> PyResult<Py<PyAny>> {
        talking(slf, "Session")
    }

    /// A suggestion (`binbun.SuggestionDraft`): `with
    /// db.suggestion("Name parse_args", rationale=..., evidence=[...]) as
    /// s:` records the writes made in it on this thread instead of making
    /// them, and makes them a suggestion labelled `label` when it ends
    /// (`s.suggestion`; nothing if an exception leaves it): a person
    /// accepts it or not. `evidence`: query results it rests on, as they
    /// were got; `thread`: the thread it answers; `supersedes`: a
    /// suggestion of this identity's it is the next version of (its label,
    /// rationale, evidence and thread kept unless given).
    #[pyo3(signature = (label = None, *, rationale = None, evidence = None, thread = None, supersedes = None))]
    fn suggestion(
        slf: &Bound<'_, Self>,
        label: Option<&str>,
        rationale: Option<&str>,
        evidence: Option<&Bound<'_, PyAny>>,
        thread: Option<&Bound<'_, PyAny>>,
        supersedes: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kwargs = PyDict::new(py);
        kwargs.set_item("rationale", rationale)?;
        kwargs.set_item("evidence", evidence)?;
        kwargs.set_item("thread", thread)?;
        kwargs.set_item("supersedes", supersedes)?;
        Ok(py
            .import("binbun._talk")?
            .getattr("SuggestionDraft")?
            .call((slf, slf.getattr("_talk")?, label), Some(&kwargs))?
            .unbind())
    }

    /// Records the writes this thread makes from now on instead of making
    /// them (`binbun.SuggestionDraft`).
    fn _record(&self, py: Python<'_>) -> PyResult<()> {
        writes::record(py, &self.db)
    }

    /// Stops recording this thread's writes: those recorded, as
    /// `edits.apply` states them.
    fn _recorded(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        writes::recorded(py, &self.db)
    }

    /// Connected (`binbun.connect(mode="local")`): the GUI's cursor, `None`
    /// if it has none; set, the GUI goes there. `CapabilityError` in
    /// process (no GUI) or if the server has no window.
    #[getter]
    fn get_cursor(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.gui(py)?.cursor(py, None)
    }

    #[setter]
    fn set_cursor(&self, py: Python<'_>, ea: Option<Address>) -> PyResult<()> {
        let Address(ea) = ea.ok_or_else(|| {
            PyValueError::new_err("the cursor goes to an address; it cannot be removed")
        })?;
        self.gui(py)?.cursor(py, Some(ea)).map(drop)
    }

    /// Connected: the GUI's selection, `(start, end)`, if one is made;
    /// as `cursor`.
    #[getter]
    fn selection(&self, py: Python<'_>) -> PyResult<Option<(u64, u64)>> {
        self.gui(py)?.selection(py)
    }

    /// A transaction: `with db.transaction("Name crypto helpers"):` makes
    /// the writes in it on this thread one undo step, made by `author`
    /// (`user`, `script:<name>`, `plugin:<id>`, `agent`; by default
    /// `script:` and the script's file name), rolled back if an exception
    /// leaves it. An inner one joins the outer. Corrections in it are
    /// analysed anew once, at commit; with `wait`, leaving it returns once
    /// the new analysis is in place.
    #[pyo3(signature = (label, *, author = None, wait = true))]
    fn transaction(
        &self,
        py: Python<'_>,
        label: &str,
        author: Option<&str>,
        wait: bool,
    ) -> PyResult<Transaction> {
        Transaction::new(py, &self.db, label, author, wait)
    }

    /// Undoes this install's last change not undone (a key changed by
    /// someone since is left alone: `HistoryEntry.skipped`); the change
    /// written, `None` if nothing is left to undo. With `wait`, an undone
    /// correction's new analysis is waited for.
    #[pyo3(signature = (*, wait = true))]
    fn undo(&self, py: Python<'_>, wait: bool) -> PyResult<Option<HistoryEntry>> {
        writes::replay(py, &self.db, false, wait)
    }

    /// Makes the last change undone again; as `undo`.
    #[pyo3(signature = (*, wait = true))]
    fn redo(&self, py: Python<'_>, wait: bool) -> PyResult<Option<HistoryEntry>> {
        writes::replay(py, &self.db, true, wait)
    }

    /// The changes, newest first: every author's.
    #[getter]
    fn history(&self, py: Python<'_>) -> PyResult<Vec<HistoryEntry>> {
        writes::history(py, &self.db)
    }

    /// Connected (`binbun.connect(mode="local")`): commits the run group
    /// (the writes made outside a transaction so far, one undo step in
    /// the GUI); the change it made. In process: `None` (each write is a
    /// step of its own).
    fn commit(&self, py: Python<'_>) -> PyResult<Option<HistoryEntry>> {
        match self.db.link() {
            Some(link) => Ok(link.finish(py)?.map(HistoryEntry::from)),
            None => Ok(None),
        }
    }

    /// Serves this database over the user's socket, as the GUI serves
    /// its own (`binbun.connect()` finds it), until the `Server` is
    /// closed; with `ui`, a window's cursor and selection too (set on the
    /// `Server`), which clients read as the GUI's.
    #[pyo3(signature = (*, ui = false))]
    fn serve(&self, py: Python<'_>, ui: bool) -> PyResult<Server> {
        Server::start(py, &self.db, ui)
    }

    /// Follows `connection`'s server (`binbun.connect(mode="local")`).
    #[pyo3(name = "_follow")]
    fn follow(&self, py: Python<'_>, connection: &Connection) -> PyResult<()> {
        follow_with(py, &self.db, connection)
    }

    /// The C of `function` (a `Function` or an entry) in `view` (default:
    /// as opened): a `CDocument`. Decompiled once, kept.
    #[pyo3(signature = (function, *, view = None, timeout = None))]
    fn decompile(
        &self,
        py: Python<'_>,
        function: Entry,
        view: Option<&Bound<'_, PyAny>>,
        timeout: Option<f64>,
    ) -> PyResult<CDocument> {
        let view = view_of(view, self.db.view)?;
        decompile(py, &self.db, function.0, view, timeout)
    }

    /// Every function's C in `view`, made on `workers` threads (default:
    /// as `binbun decompile` does): `(Function, CDocument | DecompileError)`
    /// pairs in address order.
    #[pyo3(signature = (*, view = None, workers = None))]
    fn decompile_all(
        &self,
        py: Python<'_>,
        view: Option<&Bound<'_, PyAny>>,
        workers: Option<usize>,
    ) -> PyResult<DecompileAll> {
        let view = view_of(view, self.db.view)?;
        DecompileAll::start(py, &self.db, view, workers)
    }
}

impl Database {
    /// The connection to the GUI this database follows.
    ///
    /// # Errors
    ///
    /// It follows none ([`Raise::Capability`]).
    fn gui(&self, py: Python<'_>) -> PyResult<Arc<Link>> {
        self.db.link().ok_or_else(|| {
            Raise::Capability.err(
                py,
                "the cursor and selection are a GUI's: this database is open in process \
                 (binbun.connect() connects to a GUI)",
            )
        })
    }
}

/// `binbun._talk`'s class `class` over `database`'s conversation calls.
///
/// # Errors
///
/// The package cannot be imported.
fn talking(database: &Bound<'_, Database>, class: &str) -> PyResult<Py<PyAny>> {
    let call = database.getattr("_talk")?;
    Ok(database
        .py()
        .import("binbun._talk")?
        .getattr(class)?
        .call1((call,))?
        .unbind())
}

/// The C of the function at `entry` of `db` in `view`.
///
/// # Errors
///
/// No function starts there; it does not decompile
/// ([`Raise::Decompile`]); the timeout; Ctrl-C.
pub(crate) fn decompile(
    py: Python<'_>,
    db: &Arc<Db>,
    entry: u64,
    view: View,
    timeout: Option<f64>,
) -> PyResult<CDocument> {
    touch(entry);
    let session = db.analysed(py)?;
    let id = Db::function_id(&session, entry)
        .ok_or_else(|| Raise::NoFunction.err(py, format!("no function starts at {entry:#x}")))?;
    let document = document(py, &session, id, view, timeout)?
        .map_err(|message| Raise::Decompile.err(py, message))?;
    Ok(CDocument::new(db, document, session.revision()))
}

/// Function `id`'s document in `view`, made on a thread of its own while
/// this one waits (Ctrl-C and `timeout` stop the wait, not the work).
///
/// # Errors
///
/// The timeout; Ctrl-C.
pub(crate) fn document(
    py: Python<'_>,
    session: &Arc<Session>,
    id: FunctionId,
    view: View,
    timeout: Option<f64>,
) -> PyResult<Result<Arc<Document>, String>> {
    let (sender, received) = mpsc::channel();
    let working = Arc::clone(session);
    thread::Builder::new()
        .name("binbun-py-decompile".to_owned())
        .spawn(move || {
            let _ = sender.send(working.document_here(id, view));
        })
        .map_err(|error| Raise::Binbun.err(py, format!("cannot start a thread: {error}")))?;
    wait_for(
        py,
        timeout,
        "decompiling",
        move |slice| match received.recv_timeout(slice) {
            Ok(document) => Some(document),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => Some(Err("the decompiler stopped".to_owned())),
        },
        || {},
    )
}
