//! `db.functions` ([`Functions`]: `get_at`, `get_containing`,
//! `get_by_name`, `create`, `remove`, …), a function's handle
//! ([`Function`], keyed by its entry and found again on each use)
//! and its blocks ([`Block`]).

use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, PoisonError};

use binbun::Database as Engine;
use binbun::calls::Node as Callee;
use binbun::cfg::{
    Block as EngineBlock, BlockId, EdgeKind, Exit, Function as EngineFunction, FunctionId,
};
use binbun_protocol::{Correction, Write};
use binbun_session::{Session, Typed, Unit};
use pyo3::prelude::*;

use crate::database::{Address, Db, Entry, decompile, touch, view_of};
use crate::document::CDocument;
use crate::errors::{Raise, named};
use crate::facts::{self, Explanation, Origins, Run, Stages, Verification};
use crate::signatures::{SignatureMatch, name_source};
use crate::writes::write;
use crate::xrefs::{Xref, to_ea, xref};

/// The functions of a database, in address order: iterable, sized,
/// indexed by entry (`db.functions[0x401000]`), with `get_*` lookups
/// and the writes that name, type, create and remove functions.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Functions {
    db: Arc<Db>,
}

impl Functions {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }

    /// A handle of the function at `entry`.
    fn handle(&self, entry: u64) -> Function {
        Function::new(&self.db, entry)
    }

    /// The entries, sorted.
    fn sorted(&self, py: Python<'_>) -> PyResult<(Arc<Session>, Vec<u64>)> {
        let session = self.db.analysed(py)?;
        let mut entries: Vec<u64> = session
            .database()
            .map(|db| db.functions().map(|(_, f)| f.entry).collect())
            .unwrap_or_default();
        entries.sort_unstable();
        Ok((session, entries))
    }

    /// The functions with a block holding `ea`, by entry (none if no
    /// segment holds it).
    fn holding(&self, py: Python<'_>, ea: u64) -> PyResult<Vec<u64>> {
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let program = database.program();
        let holders = self.db.holders(&session, database);
        let mut entries: Vec<u64> = program
            .block_containing(ea)
            .and_then(|block| holders.get(&block))
            .into_iter()
            .flatten()
            .filter_map(|&id| database.function(id).map(|f| f.entry))
            .collect();
        entries.sort_unstable();
        Ok(entries)
    }
}

/// The engine's database of `session`.
pub(crate) fn engine<'s>(py: Python<'_>, session: &'s Session) -> PyResult<&'s Engine<'s>> {
    session
        .database()
        .ok_or_else(|| Raise::NotAnalysed.err(py, "the functions are not recovered yet"))
}

#[pymethods]
impl Functions {
    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        let session = self.db.analysed(py)?;
        Ok(session.database().map_or(0, |db| db.functions().count()))
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<FunctionIter> {
        let (session, entries) = self.sorted(py)?;
        Ok(FunctionIter {
            db: Arc::clone(&self.db),
            analysis: session.revision().analysis,
            entries,
            next: Mutex::new(0),
        })
    }

    fn __contains__(&self, py: Python<'_>, entry: Entry) -> PyResult<bool> {
        let session = self.db.analysed(py)?;
        Ok(Db::function_id(&session, entry.0).is_some())
    }

    /// The function starting exactly at `entry` (a `Function` or an
    /// `int`); `NoFunctionError` (a `KeyError`) if none does.
    fn __getitem__(&self, py: Python<'_>, entry: Entry) -> PyResult<Function> {
        if self.__contains__(py, entry)? {
            Ok(self.handle(entry.0))
        } else {
            Err(Raise::NoFunction.err(py, format!("no function starts at {:#x}", entry.0)))
        }
    }

    /// Every function, in address order.
    fn get_all(&self, py: Python<'_>) -> PyResult<FunctionIter> {
        self.__iter__(py)
    }

    /// The function holding `ea`: the one starting
    /// there, else of those whose blocks hold it the one with the greatest
    /// entry below it; `None` if none does (or no segment holds `ea`).
    fn get_at(&self, py: Python<'_>, ea: Address) -> PyResult<Option<Function>> {
        let holding = self.holding(py, ea.0)?;
        let at = holding
            .iter()
            .copied()
            .find(|&entry| entry == ea.0)
            .or_else(|| holding.iter().copied().filter(|&e| e <= ea.0).max())
            .or_else(|| holding.first().copied());
        Ok(at.map(|entry| self.handle(entry)))
    }

    /// Every function whose blocks hold `ea` (blocks can be shared), by
    /// entry (none if no segment holds `ea`).
    fn get_containing(&self, py: Python<'_>, ea: Address) -> PyResult<Vec<Function>> {
        Ok(self
            .holding(py, ea.0)?
            .into_iter()
            .map(|entry| self.handle(entry))
            .collect())
    }

    /// The functions whose entries are in `start..end`, in address order.
    fn get_between(&self, py: Python<'_>, start: Address, end: Address) -> PyResult<Vec<Function>> {
        let (_, entries) = self.sorted(py)?;
        Ok(entries
            .into_iter()
            .filter(|entry| (start.0..end.0).contains(entry))
            .map(|entry| self.handle(entry))
            .collect())
    }

    /// The first function whose entry is after `ea`.
    fn get_next(&self, py: Python<'_>, ea: Address) -> PyResult<Option<Function>> {
        let (_, entries) = self.sorted(py)?;
        let i = entries.partition_point(|&entry| entry <= ea.0);
        Ok(entries.get(i).map(|&entry| self.handle(entry)))
    }

    /// The function named `name`: the user's name, a symbol, or
    /// `sub_XXXX`.
    fn get_by_name(&self, py: Python<'_>, name: &str) -> PyResult<Option<Function>> {
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let users = session.overlay();
        let named = users
            .names
            .iter()
            .find(|&(&address, given)| given == name && database.function_at(address).is_some())
            .map(|(&address, _)| address)
            .or_else(|| {
                database
                    .functions()
                    .map(|(_, f)| f.entry)
                    .find(|&entry| database.data_name(entry).as_deref() == Some(name))
            })
            .or_else(|| {
                let hex = name.strip_prefix("sub_")?;
                let entry = u64::from_str_radix(hex, 16).ok()?;
                database.function_at(entry).map(|_| entry)
            });
        Ok(named.map(|entry| self.handle(entry)))
    }

    /// Every function's entry, sorted (no handle per function).
    fn entries(&self, py: Python<'_>) -> PyResult<Vec<u64>> {
        Ok(self.sorted(py)?.1)
    }

    /// Names `function` (a `Function` or an entry) `name` (`None` or
    /// empty: its own name again).
    fn set_name(&self, py: Python<'_>, function: Entry, name: Option<String>) -> PyResult<()> {
        let entry = function.0;
        write(py, &self.db, &Write::FunctionName { entry, name }).map(drop)
    }

    /// Gives `function` the prototype C `c` (`None`: as analysis finds
    /// it): it and its callers are decompiled again with it.
    /// `CDeclarationError` (with `.span`) if the C is refused.
    fn set_prototype(&self, py: Python<'_>, function: Entry, c: Option<String>) -> PyResult<()> {
        let entry = function.0;
        write(py, &self.db, &Write::Prototype { entry, c }).map(drop)
    }

    /// Names the frame slot of `function` at `offset` (from the stack
    /// pointer on entry) `name` in the listing.
    fn set_frame_name(
        &self,
        py: Python<'_>,
        function: Entry,
        offset: i64,
        name: Option<String>,
    ) -> PyResult<()> {
        let entry = function.0;
        write(
            py,
            &self.db,
            &Write::SlotName {
                entry,
                offset,
                name,
            },
        )
        .map(drop)
    }

    /// A function starting at `ea` (the GUI's `P`), ending at `end` if given:
    /// a correction (the binary is analysed anew).
    #[pyo3(signature = (ea, *, end = None))]
    fn create(&self, py: Python<'_>, ea: Address, end: Option<Address>) -> PyResult<()> {
        let correction = Correction::Function {
            entry: ea.0,
            end: end.map(|end| end.0),
        };
        write(py, &self.db, &Write::Correction { correction }).map(drop)
    }

    /// `function` ending at `end` (`None`: where recovery ends it; Edit
    /// Function): a correction.
    fn set_end(&self, py: Python<'_>, function: Entry, end: Option<Address>) -> PyResult<()> {
        let correction = Correction::End {
            entry: function.0,
            end: end.map(|end| end.0),
        };
        write(py, &self.db, &Write::Correction { correction }).map(drop)
    }

    /// No function at `function`'s entry (Delete Function; its code stays
    /// code): a correction.
    fn remove(&self, py: Python<'_>, function: Entry) -> PyResult<()> {
        let correction = Correction::Delete { entry: function.0 };
        write(py, &self.db, &Write::Correction { correction }).map(drop)
    }
}

/// An iteration over the functions, in address order. The analysis it
/// started on must stay: `StaleError` if another is swapped in.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct FunctionIter {
    db: Arc<Db>,
    analysis: u64,
    entries: Vec<u64>,
    next: Mutex<usize>,
}

#[pymethods]
impl FunctionIter {
    fn __iter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __next__(&self, py: Python<'_>) -> PyResult<Option<Function>> {
        if self.db.session(py)?.revision().analysis != self.analysis {
            return Err(Raise::Stale.err(py, "the analysis changed during the iteration"));
        }
        let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = self.entries.get(*next).copied();
        *next += 1;
        Ok(entry.map(|entry| Function::new(&self.db, entry)))
    }

    fn __len__(&self) -> usize {
        self.entries.len()
    }
}

/// A function, by its entry: found again on each use (a function gone
/// after a re-analysis raises `FunctionGoneError`). Equal handles name
/// the same entry of the same database.
#[pyclass(frozen, eq, hash, module = "binbun._native")]
#[derive(Clone, Debug)]
pub(crate) struct Function {
    pub(crate) db: Arc<Db>,
    /// The entry.
    #[pyo3(get)]
    pub(crate) entry: u64,
}

impl PartialEq for Function {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.db, &other.db) && self.entry == other.entry
    }
}

impl Eq for Function {}

impl Hash for Function {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.db).hash(state);
        self.entry.hash(state);
    }
}

impl Function {
    pub(crate) fn new(db: &Arc<Db>, entry: u64) -> Self {
        Self {
            db: Arc::clone(db),
            entry,
        }
    }

    /// The session and the function's id now.
    ///
    /// # Errors
    ///
    /// Closed; no function starts at the entry now
    /// ([`Raise::FunctionGone`]).
    pub(crate) fn resolve(&self, py: Python<'_>) -> PyResult<(Arc<Session>, FunctionId)> {
        touch(self.entry);
        let session = self.db.analysed(py)?;
        let id = Db::function_id(&session, self.entry).ok_or_else(|| {
            Raise::FunctionGone.err(py, format!("no function starts at {:#x} now", self.entry))
        })?;
        Ok((session, id))
    }

    /// The function's name in the image (a symbol, an import thunk's
    /// import), else `sub_XXXX`.
    fn default_name_of(database: &Engine<'_>, entry: u64) -> String {
        database
            .data_name(entry)
            .unwrap_or_else(|| format!("sub_{entry:X}"))
    }

    /// The functions `id`'s calls reach (`callees`) or that call it,
    /// each once, by entry.
    fn related(&self, py: Python<'_>, callees: bool) -> PyResult<Vec<Self>> {
        let (session, id) = self.resolve(py)?;
        let database = engine(py, &session)?;
        let graph = py.detach(|| database.calls());
        let ids: Vec<FunctionId> = if callees {
            graph
                .callees(id)
                .iter()
                .filter_map(|call| match call.callee {
                    Callee::Function(callee) => Some(callee),
                    Callee::Import(_) => None,
                })
                .collect()
        } else {
            graph
                .callers(Callee::Function(id))
                .map(|call| call.caller)
                .collect()
        };
        let mut entries: Vec<u64> = ids
            .into_iter()
            .filter_map(|id| database.function(id).map(|f| f.entry))
            .collect();
        entries.sort_unstable();
        entries.dedup();
        Ok(entries
            .into_iter()
            .map(|entry| Self::new(&self.db, entry))
            .collect())
    }
}

#[pymethods]
impl Function {
    fn __repr__(&self, py: Python<'_>) -> String {
        let name = self.name(py).unwrap_or_default();
        format!("<binbun.Function {:#x} {name}>", self.entry)
    }

    /// Its name: the user's, else [`Self::default_name`].
    #[getter]
    fn name(&self, py: Python<'_>) -> PyResult<String> {
        let (session, _) = self.resolve(py)?;
        if let Some(name) = session.edits().name(self.entry) {
            return Ok(name.to_owned());
        }
        Ok(Self::default_name_of(engine(py, &session)?, self.entry))
    }

    /// Its name without the user's: the image's, else `sub_XXXX`.
    #[getter]
    fn default_name(&self, py: Python<'_>) -> PyResult<String> {
        let (session, _) = self.resolve(py)?;
        Ok(Self::default_name_of(engine(py, &session)?, self.entry))
    }

    /// The image's name for it (a symbol, an import thunk's import), if
    /// it has one.
    #[getter]
    fn symbol(&self, py: Python<'_>) -> PyResult<Option<String>> {
        let (session, _) = self.resolve(py)?;
        Ok(engine(py, &session)?.data_name(self.entry))
    }

    /// The user's name, if given.
    #[getter]
    fn user_name(&self, py: Python<'_>) -> PyResult<Option<String>> {
        let (session, _) = self.resolve(py)?;
        Ok(session.edits().name(self.entry).map(str::to_owned))
    }

    /// Where its name comes from: `"user"` (or `"script"`, `"plugin"`,
    /// `"agent"`: an edit by one), `"signature"` (a library signature),
    /// `"symbol"`, `"debug"`; `None` for binbun's own (`sub_…`).
    #[getter]
    fn name_source(&self, py: Python<'_>) -> PyResult<Option<&'static str>> {
        let (session, _) = self.resolve(py)?;
        Ok(name_source(&session, self.entry))
    }

    /// What a library signature says of it, if one matched (a match the
    /// user rejected says so).
    #[getter]
    fn signature_match(&self, py: Python<'_>) -> PyResult<Option<SignatureMatch>> {
        let (session, _) = self.resolve(py)?;
        Ok(session.signature(self.entry).map(SignatureMatch::of))
    }

    /// The user's prototype, as C, if given.
    #[getter]
    fn prototype(&self, py: Python<'_>) -> PyResult<Option<String>> {
        let (session, _) = self.resolve(py)?;
        Ok(session.type_of(&Typed::Prototype(self.entry)))
    }

    /// Whether it returns.
    #[getter]
    fn returns(&self, py: Python<'_>) -> PyResult<bool> {
        self.with(py, |f| f.returns)
    }

    /// Its parts placed apart (cold parts), by start.
    #[getter]
    fn parts(&self, py: Python<'_>) -> PyResult<Vec<u64>> {
        self.with(py, |f| f.parts.clone())
    }

    /// Its exception landing pads.
    #[getter]
    fn landing_pads(&self, py: Python<'_>) -> PyResult<Vec<u64>> {
        self.with(py, |f| f.landing_pads.clone())
    }

    /// Its funclets.
    #[getter]
    fn funclets(&self, py: Python<'_>) -> PyResult<Vec<u64>> {
        self.with(py, |f| f.funclets.clone())
    }

    /// The function it is a part of, if it is one.
    #[getter]
    fn part_of(&self, py: Python<'_>) -> PyResult<Option<Self>> {
        let entry = self.with(py, |f| f.part_of)?;
        Ok(entry.map(|entry| Self::new(&self.db, entry)))
    }

    /// Its blocks, by start.
    #[getter]
    fn blocks(&self, py: Python<'_>) -> PyResult<Vec<Block>> {
        let (session, id) = self.resolve(py)?;
        let database = engine(py, &session)?;
        let program = database.program();
        let mut starts: Vec<u64> = database
            .function(id)
            .map(|f| {
                f.blocks
                    .iter()
                    .filter_map(|&b| program.blocks.get(b).map(|b| b.start))
                    .collect()
            })
            .unwrap_or_default();
        starts.sort_unstable();
        Ok(starts
            .into_iter()
            .map(|start| Block {
                db: Arc::clone(&self.db),
                start,
            })
            .collect())
    }

    /// Its blocks' address ranges, merged: `(start, end)` pairs.
    #[getter]
    fn ranges(&self, py: Python<'_>) -> PyResult<Vec<(u64, u64)>> {
        let (session, id) = self.resolve(py)?;
        let database = engine(py, &session)?;
        let program = database.program();
        let mut ranges: Vec<(u64, u64)> = database
            .function(id)
            .map(|f| {
                f.blocks
                    .iter()
                    .filter_map(|&b| program.blocks.get(b).map(|b| (b.start, b.end)))
                    .collect()
            })
            .unwrap_or_default();
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        Ok(merged)
    }

    /// The compilation unit the debug information puts it in, if any.
    #[getter]
    fn source_unit(&self, py: Python<'_>) -> PyResult<Option<String>> {
        let (session, _) = self.resolve(py)?;
        Ok(session.source_unit(self.entry).map(Unit::path))
    }

    /// The functions it calls, by entry.
    fn callees(&self, py: Python<'_>) -> PyResult<Vec<Self>> {
        self.related(py, true)
    }

    /// The functions calling it, by entry.
    fn callers(&self, py: Python<'_>) -> PyResult<Vec<Self>> {
        self.related(py, false)
    }

    /// The references to its entry: a `binbun.XrefsTo`.
    fn xrefs_to(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        to_ea(py, &self.db, self.entry, None)
    }

    /// The references it makes.
    fn xrefs_from(&self, py: Python<'_>) -> PyResult<Vec<Xref>> {
        let (session, id) = self.resolve(py)?;
        let database = engine(py, &session)?;
        let references = py.detach(|| database.references());
        Ok(references
            .from_function(id)
            .map(|reference| xref(&self.db, database, reference))
            .collect())
    }

    /// Its C in `view` (default: as opened): a `CDocument`.
    #[pyo3(signature = (*, view = None, timeout = None))]
    fn decompile(
        &self,
        py: Python<'_>,
        view: Option<&Bound<'_, PyAny>>,
        timeout: Option<f64>,
    ) -> PyResult<CDocument> {
        let view = view_of(view, self.db.view)?;
        decompile(py, &self.db, self.entry, view, timeout)
    }

    /// Whether its C does what its machine code does (`binbun verify`,
    /// the interactive check's fuel): a `Verification`. On a processor's
    /// `profile` (a shipped profile's name or a file) if given.
    #[pyo3(signature = (*, view = None, profile = None, timeout = None))]
    fn verify(
        &self,
        py: Python<'_>,
        view: Option<&Bound<'_, PyAny>>,
        profile: Option<&str>,
        timeout: Option<f64>,
    ) -> PyResult<Verification> {
        facts::verify(py, self, view_of(view, self.db.view)?, profile, timeout)
    }

    /// Why each variable has its type and name (`binbun why`).
    #[pyo3(signature = (*, view = None, timeout = None))]
    fn why(
        &self,
        py: Python<'_>,
        view: Option<&Bound<'_, PyAny>>,
        timeout: Option<f64>,
    ) -> PyResult<Explanation> {
        facts::why(py, self, view_of(view, self.db.view)?, timeout)
    }

    /// Where a value comes from and goes (`binbun origin`): of a
    /// `CVariable`, or a `CToken`'s node.
    #[pyo3(signature = (of, *, view = None, timeout = None))]
    fn origins(
        &self,
        py: Python<'_>,
        of: &Bound<'_, PyAny>,
        view: Option<&Bound<'_, PyAny>>,
        timeout: Option<f64>,
    ) -> PyResult<Origins> {
        facts::origins(py, self, of, view_of(view, self.db.view)?, timeout)
    }

    /// Its C and its machine code run from an example state (`binbun
    /// run`): the state as TOML (`None`: a scratch state); on a
    /// processor's `profile` (a shipped profile's name or a file) if given.
    #[pyo3(signature = (state = None, *, view = None, profile = None, timeout = None))]
    fn run(
        &self,
        py: Python<'_>,
        state: Option<&str>,
        view: Option<&Bound<'_, PyAny>>,
        profile: Option<&str>,
        timeout: Option<f64>,
    ) -> PyResult<Run> {
        facts::run(
            py,
            self,
            state,
            view_of(view, self.db.view)?,
            profile,
            timeout,
        )
    }

    /// It through every stage of decompilation, as text (`binbun
    /// stages`): a `binbun.ir.Stages`. Unstable.
    #[pyo3(signature = (*, view = None, timeout = None))]
    fn stages(
        &self,
        py: Python<'_>,
        view: Option<&Bound<'_, PyAny>>,
        timeout: Option<f64>,
    ) -> PyResult<Stages> {
        facts::stages(py, self, view_of(view, self.db.view)?, timeout)
    }
}

impl Function {
    /// `read` of the engine's function now.
    fn with<T>(&self, py: Python<'_>, read: impl FnOnce(&EngineFunction) -> T) -> PyResult<T> {
        let (session, id) = self.resolve(py)?;
        let database = engine(py, &session)?;
        database
            .function(id)
            .map(read)
            .ok_or_else(|| Raise::FunctionGone.err(py, format!("{:#x}", self.entry)))
    }
}

/// A basic block, by its start: found again on each use.
#[pyclass(frozen, eq, hash, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Block {
    db: Arc<Db>,
    /// Its first instruction's address.
    #[pyo3(get)]
    pub(crate) start: u64,
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.db, &other.db) && self.start == other.start
    }
}

impl Eq for Block {}

impl Hash for Block {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.db).hash(state);
        self.start.hash(state);
    }
}

impl Block {
    /// `read` of the engine's block now, with its id (and the session and
    /// database it is of).
    fn with<T>(
        &self,
        py: Python<'_>,
        read: impl FnOnce(&Session, &Engine<'_>, BlockId, &EngineBlock) -> T,
    ) -> PyResult<T> {
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let program = database.program();
        let id = program.block_at(self.start).ok_or_else(|| {
            Raise::Stale.err(py, format!("no block starts at {:#x} now", self.start))
        })?;
        let block = program
            .blocks
            .get(id)
            .ok_or_else(|| Raise::Stale.err(py, format!("{:#x}", self.start)))?;
        Ok(read(&session, database, id, block))
    }
}

#[pymethods]
impl Block {
    fn __repr__(&self) -> String {
        format!("<binbun.Block {:#x}>", self.start)
    }

    /// The address after its last instruction.
    #[getter]
    fn end(&self, py: Python<'_>) -> PyResult<u64> {
        self.with(py, |_, _, _, block| block.end)
    }

    /// How many instructions it has.
    #[getter]
    fn count(&self, py: Python<'_>) -> PyResult<u32> {
        self.with(py, |_, _, _, block| block.instructions)
    }

    /// How it ends: `next`, `jump`, `branch`, `call`, `return`, `stop`,
    /// `invalid` or `limit`.
    #[getter]
    fn exit(&self, py: Python<'_>) -> PyResult<&'static str> {
        self.with(py, |_, _, _, block| exit_name(&block.exit))
    }

    /// Where control goes next: `binbun.Successor(kind, address)`s, kind
    /// one of `next`, `jump`, `taken`, `not_taken`, `call_return`,
    /// `table`, `unwind`.
    #[getter]
    fn successors<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        let successors: Vec<(&'static str, u64)> = self.with(py, |_, database, id, _| {
            database
                .program()
                .successors(id)
                .map(|(kind, to)| (edge_name(kind), to))
                .collect()
        })?;
        successors
            .into_iter()
            .map(|fields| named(py, "Successor", fields))
            .collect()
    }

    /// The resolved targets of its computed jump, if it ends in one.
    #[getter]
    fn table(&self, py: Python<'_>) -> PyResult<Option<Vec<u64>>> {
        self.with(py, |_, database, id, _| {
            database.program().table(id).map(|t| t.targets.clone())
        })
    }

    /// The functions it is part of, by entry.
    #[getter]
    fn functions(&self, py: Python<'_>) -> PyResult<Vec<Function>> {
        let entries = self.with(py, |session, database, id, _| {
            let mut entries: Vec<u64> = self
                .db
                .holders(session, database)
                .get(&id)
                .into_iter()
                .flatten()
                .filter_map(|&f| database.function(f).map(|f| f.entry))
                .collect();
            entries.sort_unstable();
            entries
        })?;
        Ok(entries
            .into_iter()
            .map(|entry| Function::new(&self.db, entry))
            .collect())
    }
}

/// `exit`'s name.
const fn exit_name(exit: &Exit) -> &'static str {
    match exit {
        Exit::Next => "next",
        Exit::Jump(_) => "jump",
        Exit::Branch(_) => "branch",
        Exit::Call { .. } => "call",
        Exit::Return => "return",
        Exit::Stop => "stop",
        Exit::Invalid => "invalid",
        Exit::Limit => "limit",
    }
}

/// `kind`'s name.
const fn edge_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Next => "next",
        EdgeKind::Jump => "jump",
        EdgeKind::Taken => "taken",
        EdgeKind::NotTaken => "not_taken",
        EdgeKind::CallReturn => "call_return",
        EdgeKind::Table => "table",
        EdgeKind::Unwind => "unwind",
    }
}
