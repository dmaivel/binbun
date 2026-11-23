//! A function's C as a value ([`CDocument`]): its text, lines and tokens
//! with the instructions each came from (the session's provenance), its
//! variables; and every function's C made on threads ([`DecompileAll`]).

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, TryLockError};
use std::thread;

use binbun::cfg::FunctionId;
use binbun::decompile::threads as default_threads;
use binbun_ast::ir::{Node, VarId, VarKind};
use binbun_print::c::Image as _;
use binbun_print::c::type_names;
use binbun_print::document::TokenKind;
use binbun_print::layout::render;
use binbun_protocol::talk::EvidenceRefData;
use binbun_protocol::{VariableRef, Viewed, Write};
use binbun_session::{Document, Revision as SessionRevision, View};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::database::{Address, Db, Revision, revision, view_object};
use crate::errors::{Raise, named};
use crate::functions::{Function, engine};
use crate::remote::cited;
use crate::wait::wait_for;
use crate::writes::write;

/// `kind`'s name.
const fn token_kind(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::ControlKeyword => "control_keyword",
        TokenKind::Keyword => "keyword",
        TokenKind::Type => "type",
        TokenKind::BuiltinType => "builtin_type",
        TokenKind::Function => "function",
        TokenKind::Local => "local",
        TokenKind::Parameter => "parameter",
        TokenKind::Global => "global",
        TokenKind::Field => "field",
        TokenKind::Macro => "macro",
        TokenKind::Number => "number",
        TokenKind::String => "string",
        TokenKind::Operator => "operator",
        TokenKind::Punctuation => "punctuation",
        TokenKind::Comment => "comment",
        TokenKind::Label => "label",
    }
}

/// `kind`'s coarse class, as `CToken.kind` named them before the kinds
/// were split: `keyword`, `identifier`, `type`, `literal`, `operator`,
/// `punctuation`, `comment` or `label`.
const fn token_category(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::ControlKeyword | TokenKind::Keyword => "keyword",
        TokenKind::Function
        | TokenKind::Local
        | TokenKind::Parameter
        | TokenKind::Global
        | TokenKind::Field
        | TokenKind::Macro => "identifier",
        TokenKind::Type | TokenKind::BuiltinType => "type",
        TokenKind::Number | TokenKind::String => "literal",
        TokenKind::Operator => "operator",
        TokenKind::Punctuation => "punctuation",
        TokenKind::Comment => "comment",
        TokenKind::Label => "label",
    }
}

/// `node` as text: `expr 12`, `stmt 3`, `var 1`, `type 7`.
fn node_text(node: Node) -> String {
    match node {
        Node::Expr(e) => format!("expr {}", e.0),
        Node::Stmt(s) => format!("stmt {}", s.0),
        Node::Var(v) => format!("var {}", v.0),
        Node::Type(t) => format!("type {}", t.0),
    }
}

/// One function's C as printed, a value of the revision it was printed
/// at: its text, lines and tokens, each with the machine instructions it
/// came from.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct CDocument {
    db: Arc<Db>,
    pub(crate) document: Arc<Document>,
    /// The revision it was printed at.
    #[pyo3(get)]
    revision: Revision,
}

impl CDocument {
    pub(crate) fn new(db: &Arc<Db>, document: Arc<Document>, printed: SessionRevision) -> Self {
        Self {
            db: Arc::clone(db),
            document,
            revision: revision(printed),
        }
    }

    /// Token `s`.
    fn token(&self, s: usize) -> Option<CToken> {
        let span = self.document.spans.get(s)?;
        Some(CToken {
            index: s,
            start: span.range.start,
            end: span.range.end,
            kind: token_kind(span.kind),
            category: token_category(span.kind),
            automatic: span.automatic,
            cast: span.cast,
            node: span.node,
            text: self
                .document
                .text
                .get(span.range.clone())
                .unwrap_or("")
                .to_owned(),
            addresses: self.document.span_addresses(s).to_vec(),
        })
    }

    /// Line `n`.
    fn line(&self, n: usize) -> Option<CLine> {
        let line = self.document.lines().get(n)?;
        Some(CLine {
            db: Arc::clone(&self.db),
            entry: self.document.entry,
            view: self.document.view,
            number: n,
            text: self.document.line_text(n).to_owned(),
            addresses: line.addresses.clone(),
        })
    }
}

#[pymethods]
impl CDocument {
    fn __repr__(&self) -> String {
        format!(
            "<binbun.CDocument {:#x}, {} lines>",
            self.document.entry,
            self.document.lines().len()
        )
    }

    fn __str__(&self) -> String {
        self.document.text.clone()
    }

    /// The function.
    #[getter]
    fn function(&self) -> Function {
        Function::new(&self.db, self.document.entry)
    }

    /// The view: a `View`.
    #[getter]
    fn view<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        view_object(py, self.document.view)
    }

    /// The C file, as `binbun decompile` prints the function (with the
    /// user's names and comments).
    #[getter]
    fn text(&self) -> String {
        self.document.text.clone()
    }

    /// The lines, each with the instructions it came from.
    #[getter]
    fn lines(&self) -> Vec<CLine> {
        (0..self.document.lines().len())
            .filter_map(|n| self.line(n))
            .collect()
    }

    /// The tokens, in order, each with its node and instructions.
    #[getter]
    fn tokens(&self) -> Vec<CToken> {
        (0..self.document.spans.len())
            .filter_map(|s| self.token(s))
            .collect()
    }

    /// The user's comments printed: `binbun.CComment(line, address,
    /// text)`s, one per line of a comment.
    #[getter]
    fn comments<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        let provenance = &self.document.provenance;
        self.document
            .comments
            .iter()
            .filter_map(|(&s, (address, text))| {
                let line = provenance.line_of_span(s)?;
                Some(named(py, "CComment", (line, *address, text.as_str())))
            })
            .collect()
    }

    /// What the C contains: `{"casts": …, "gotos": …, "escapes": …}`.
    #[getter]
    fn counts<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let counts = PyDict::new(py);
        counts.set_item("casts", self.document.counts.casts)?;
        counts.set_item("gotos", self.document.counts.gotos)?;
        counts.set_item("escapes", self.document.counts.escapes)?;
        Ok(counts)
    }

    /// The variables printed, in order of first use.
    #[getter]
    fn variables(&self, py: Python<'_>) -> PyResult<Vec<CVariable>> {
        let session = self.db.session(py)?;
        let database = engine(py, &session)?;
        let document = &self.document;
        let l2 = &document.decompiled.l2;
        let style = session.style();
        let long = database.data().long_width();
        let names = database
            .declarations()
            .and_then(|declarations| {
                let documents = type_names(&l2.types, declarations, &style, long).ok()?;
                Some(
                    documents
                        .iter()
                        .map(|d| d.as_ref().map(|d| render(d, &style).trim().to_owned()))
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap_or_default();
        let mut printed: BTreeMap<VarId, String> = BTreeMap::new();
        let mut order = Vec::new();
        for span in &document.spans {
            if let Some(Node::Var(var)) = span.node
                && span.kind.is_variable()
                && !printed.contains_key(&var)
                && let Some(name) = document.text.get(span.range.clone())
            {
                printed.insert(var, name.to_owned());
                order.push(var);
            }
        }
        let function = document.function;
        Ok(order
            .into_iter()
            .filter_map(|var| {
                let variable = l2.var(var)?;
                let identity = session.variable(function, document.view, var).ok();
                Some(CVariable {
                    db: Arc::clone(&self.db),
                    view: document.view,
                    var: var.0,
                    name: printed.get(&var).cloned().unwrap_or_default(),
                    default_name: document.default_name(var).map(str::to_owned),
                    kind: match variable.kind {
                        VarKind::Parameter => "parameter",
                        VarKind::Local => "local",
                        VarKind::Global(_) => "global",
                        VarKind::Frame(_) => "frame",
                        VarKind::Environment(_) => "environment",
                    },
                    r#type: usize::try_from(variable.ty.0)
                        .ok()
                        .and_then(|ty| names.get(ty).cloned().flatten()),
                    origins: identity
                        .as_ref()
                        .map(|v| v.origins.clone())
                        .unwrap_or_default(),
                    ordinal: identity.as_ref().map_or(0, |v| v.ordinal),
                    function_entry: document.entry,
                })
            })
            .collect())
    }

    /// The lines made from the instruction at `ea`.
    fn lines_of(&self, ea: Address) -> Vec<CLine> {
        self.document
            .lines_of(ea.0)
            .filter_map(|n| self.line(n))
            .collect()
    }

    /// The token at byte `column` of line `line`, if one is there.
    fn token_at(&self, line: usize, column: usize) -> Option<CToken> {
        let at = self.document.lines().get(line)?;
        let byte = at.range.start + column;
        at.spans
            .clone()
            .find(|&s| {
                self.document
                    .spans
                    .get(s)
                    .is_some_and(|span| span.range.contains(&byte))
            })
            .and_then(|s| self.token(s))
    }

    /// The variable printed as `name`; `NoVariableError` if none is.
    fn variable(&self, py: Python<'_>, name: &str) -> PyResult<CVariable> {
        self.variables(py)?
            .into_iter()
            .find(|v| v.name == name)
            .ok_or_else(|| Raise::NoVariable.err(py, format!("no variable {name}")))
    }
}

/// A line of a function's C: as evidence (`evidence=[...]`, alone or in a
/// list of one document's lines), these lines of its function's C in its
/// view; a thread's anchor (`db.threads.create(line, ...)`), the line by
/// its first instruction. Equal lines are of the same database,
/// function, view and number, and read the same.
#[pyclass(frozen, eq, hash, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct CLine {
    db: Arc<Db>,
    /// Its function's entry.
    entry: u64,
    /// The view of the document it was read from.
    view: View,
    /// Its number, from 0.
    #[pyo3(get)]
    number: usize,
    /// Its text.
    #[pyo3(get)]
    text: String,
    /// The instructions its expressions and statements came from, sorted.
    #[pyo3(get)]
    addresses: Vec<u64>,
}

impl PartialEq for CLine {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.db, &other.db)
            && (
                self.entry,
                self.view,
                self.number,
                &self.text,
                &self.addresses,
            ) == (
                other.entry,
                other.view,
                other.number,
                &other.text,
                &other.addresses,
            )
    }
}

impl Eq for CLine {}

impl Hash for CLine {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.db).hash(state);
        let reading = self.view == View::Reading;
        (self.entry, reading, self.number, &self.text).hash(state);
    }
}

#[pymethods]
impl CLine {
    fn __repr__(&self) -> String {
        format!("CLine({}, {:?})", self.number, self.text)
    }

    /// Its function.
    #[getter]
    fn function(&self) -> Function {
        Function::new(&self.db, self.entry)
    }

    /// The view of the document it was read from: a `View`.
    #[getter]
    fn view<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        view_object(py, self.view)
    }

    /// What it is cited as: this line of its function's C.
    fn _cite(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let line = u32::try_from(self.number)
            .map_err(|_| PyValueError::new_err("the line's number is too large to cite"))?;
        cited(
            py,
            &EvidenceRefData::Lines {
                function: self.entry,
                view: Viewed::of(self.view),
                lines: vec![line],
            },
        )
    }
}

/// A token of a function's C: its bytes in the text, its kind, the L2
/// node it stands for, the instructions it came from.
#[pyclass(frozen, eq, module = "binbun._native")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CToken {
    /// Its index among the tokens.
    #[pyo3(get)]
    index: usize,
    /// Its first byte in the text.
    #[pyo3(get)]
    start: usize,
    /// The byte after it.
    #[pyo3(get)]
    end: usize,
    /// `control_keyword`, `keyword`, `type`, `builtin_type`, `function`,
    /// `local`, `parameter`, `global`, `field`, `macro`, `number`,
    /// `string`, `operator`, `punctuation`, `comment` or `label`.
    #[pyo3(get)]
    kind: &'static str,
    /// Its kind's coarse class: `keyword`, `identifier`, `type`,
    /// `literal`, `operator`, `punctuation`, `comment` or `label`.
    #[pyo3(get)]
    category: &'static str,
    /// Whether it is a name binbun made up (`v17`, `sub_401000`).
    #[pyo3(get)]
    automatic: bool,
    /// Whether it is part of a cast (its parentheses or type).
    #[pyo3(get)]
    cast: bool,
    pub(crate) node: Option<Node>,
    /// Its text.
    #[pyo3(get)]
    text: String,
    /// The instructions it stands for: its node's, else its line's.
    #[pyo3(get)]
    addresses: Vec<u64>,
}

#[pymethods]
impl CToken {
    fn __repr__(&self) -> String {
        format!("CToken({:?}, {})", self.text, self.kind)
    }

    /// The L2 node it stands for (`expr 12`, `stmt 3`, `var 1`, `type 7`),
    /// if any. Unstable.
    #[getter]
    fn node(&self) -> Option<String> {
        self.node.map(node_text)
    }
}

/// A variable of a function's C: its printed name, its default name,
/// kind and type, and its identity (what it was made from), which survives
/// re-analysis as edits do: renamed and typed by it. Equal variables have
/// the same identity and print the same.
#[pyclass(frozen, eq, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct CVariable {
    db: Arc<Db>,
    /// The view of the document it was read from.
    view: View,
    pub(crate) var: u32,
    /// Its name as printed.
    #[pyo3(get)]
    name: String,
    /// Its name without the user's.
    #[pyo3(get)]
    default_name: Option<String>,
    /// `parameter`, `local`, `global`, `frame` or `environment`.
    #[pyo3(get)]
    kind: &'static str,
    /// Its C type, if C can name it.
    #[pyo3(get, name = "type")]
    r#type: Option<String>,
    /// What it was made from (its identity, with `ordinal`).
    #[pyo3(get)]
    origins: Vec<String>,
    /// Its place among the function's variables made from the same.
    #[pyo3(get)]
    ordinal: usize,
    /// Its function's entry.
    function_entry: u64,
}

#[pymethods]
impl CVariable {
    fn __repr__(&self) -> String {
        format!("CVariable({:?}, {})", self.name, self.kind)
    }

    /// Its function.
    #[getter]
    fn function(&self) -> Function {
        Function::new(&self.db, self.function_entry)
    }

    /// The view of the document it was read from.
    #[getter]
    fn view<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        view_object(py, self.view)
    }

    /// Names it `name` (`None`: the printer's name again), in both
    /// views: the name goes to what it was made from.
    fn rename(&self, py: Python<'_>, name: Option<String>) -> PyResult<()> {
        let variable = self.reference();
        write(py, &self.db, &Write::VariableName { variable, name }).map(drop)
    }

    /// Types it as C `c` (as wide as it is; `None`: as analysis types
    /// it). `CDeclarationError` (with `.span`) if the C is refused.
    fn set_type(&self, py: Python<'_>, c: Option<String>) -> PyResult<()> {
        let variable = self.reference();
        write(py, &self.db, &Write::VariableType { variable, c }).map(drop)
    }
}

impl PartialEq for CVariable {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.db, &other.db)
            && (
                self.function_entry,
                &self.origins,
                self.ordinal,
                self.var,
                &self.name,
            ) == (
                other.function_entry,
                &other.origins,
                other.ordinal,
                other.var,
                &other.name,
            )
            && (self.view == other.view)
    }
}

impl CVariable {
    /// Its L2 variable.
    pub(crate) const fn var(&self) -> VarId {
        VarId(self.var)
    }

    /// It as a write names it: its identity and its view.
    pub(crate) fn reference(&self) -> VariableRef {
        VariableRef {
            function: self.function_entry,
            origins: self.origins.clone(),
            ordinal: self.ordinal,
            view: Viewed::of(self.view),
        }
    }
}

/// What the threads of a [`DecompileAll`] share.
#[derive(Debug)]
struct Pending {
    /// Results by position, not yet yielded.
    arrived: BTreeMap<usize, Result<Arc<Document>, String>>,
    /// The next position to yield.
    next: usize,
    received: Receiver<(usize, Result<Arc<Document>, String>)>,
}

/// Every function's C, made on threads of their own (the GIL released
/// while waiting), yielded in address order as `(Function,
/// CDocument | DecompileError)`. Dropping it stops the threads.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct DecompileAll {
    db: Arc<Db>,
    entries: Vec<u64>,
    pending: Mutex<Pending>,
    cancel: Arc<AtomicBool>,
    revision: SessionRevision,
}

impl DecompileAll {
    /// Starts `threads` threads making every function's C in `view`.
    pub(crate) fn start(
        py: Python<'_>,
        db: &Arc<Db>,
        view: View,
        threads: Option<usize>,
    ) -> PyResult<Self> {
        let session = db.analysed(py)?;
        let database = engine(py, &session)?;
        let mut functions: Vec<(u64, FunctionId)> =
            database.functions().map(|(id, f)| (f.entry, id)).collect();
        functions.sort_unstable();
        let entries = functions.iter().map(|&(entry, _)| entry).collect();
        let functions = Arc::new(functions);
        let (sender, received) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let next = Arc::new(AtomicUsize::new(0));
        for n in 0..threads.unwrap_or_else(default_threads).max(1) {
            let (sender, cancel, next) = (sender.clone(), Arc::clone(&cancel), Arc::clone(&next));
            let (session, functions) = (Arc::clone(&session), Arc::clone(&functions));
            thread::Builder::new()
                .name(format!("binbun-py-all-{n}"))
                .spawn(move || {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&(_, id)) = functions.get(i) else {
                            break;
                        };
                        if cancel.load(Ordering::Relaxed) {
                            break;
                        }
                        let result = session.document_here(id, view);
                        if sender.send((i, result)).is_err() {
                            break;
                        }
                    }
                })
                .map_err(|error| {
                    Raise::Binbun.err(py, format!("cannot start a thread: {error}"))
                })?;
        }
        Ok(Self {
            db: Arc::clone(db),
            entries,
            pending: Mutex::new(Pending {
                arrived: BTreeMap::new(),
                next: 0,
                received,
            }),
            cancel,
            revision: session.revision(),
        })
    }
}

impl Drop for DecompileAll {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

#[pymethods]
impl DecompileAll {
    fn __iter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __len__(&self) -> usize {
        self.entries.len()
    }

    fn __next__<'py>(&self, py: Python<'py>) -> PyResult<Option<(Function, Bound<'py, PyAny>)>> {
        // Never blocks with the GIL held (another thread waiting here
        // would need it back).
        let mut pending = match self.pending.try_lock() {
            Ok(pending) => pending,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(PyRuntimeError::new_err(
                    "another thread is iterating these documents",
                ));
            }
        };
        let i = pending.next;
        let Some(&entry) = self.entries.get(i) else {
            return Ok(None);
        };
        let result = if let Some(result) = pending.arrived.remove(&i) {
            result
        } else {
            let pending = &mut *pending;
            let cancel = &self.cancel;
            wait_for(
                py,
                None,
                "decompiling",
                move |slice| loop {
                    match pending.received.recv_timeout(slice) {
                        Ok((at, result)) if at == i => return Some(result),
                        Ok((at, result)) => {
                            pending.arrived.insert(at, result);
                        }
                        Err(RecvTimeoutError::Timeout) => return None,
                        Err(RecvTimeoutError::Disconnected) => {
                            return Some(Err("the decompiling threads stopped".to_owned()));
                        }
                    }
                },
                || cancel.store(true, Ordering::Relaxed),
            )?
        };
        pending.next += 1;
        let function = Function::new(&self.db, entry);
        let item = match result {
            Ok(document) => {
                Bound::new(py, CDocument::new(&self.db, document, self.revision))?.into_any()
            }
            Err(message) => Raise::Decompile.value(py, &message)?,
        };
        Ok(Some((function, item)))
    }
}
