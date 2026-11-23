//! `db.xrefs`: the engine's cross-references (`binbun xrefs`) as
//! [`Xref`] values, and in columns ([`XrefTable`]).

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use binbun::Database as Engine;
use binbun::references::{Kind, Origin, Reference};
use binbun_loader::Relocation;
use binbun_protocol::talk::EvidenceRefData;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::database::{Address, Db};
use crate::errors::member;
use crate::functions::{Function, engine};
use crate::remote::cited;

/// `kind`'s `binbun.XrefKind` value.
const fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Call => "call",
        Kind::Jump => "jump",
        Kind::Read => "read",
        Kind::Write => "write",
        Kind::Address => "address",
        Kind::Pointer(_) => "pointer",
    }
}

/// Where a pointer came from (`relocation` or `scan`), and the
/// relocation's kind.
const fn pointer_origin(kind: Kind) -> (Option<&'static str>, Option<&'static str>) {
    match kind {
        Kind::Pointer(Origin::Scan) => (Some("scan"), None),
        Kind::Pointer(Origin::Relocation(relocation)) => (
            Some("relocation"),
            Some(match relocation {
                Relocation::Relative => "relative",
                Relocation::Absolute => "absolute",
                Relocation::GlobDat => "glob_dat",
                Relocation::JumpSlot => "jump_slot",
                Relocation::Base => "base",
                Relocation::Rebase => "rebase",
            }),
        ),
        Kind::Call | Kind::Jump | Kind::Read | Kind::Write | Kind::Address => (None, None),
    }
}

/// A cross-reference: made at `from_ea` (an instruction, or a pointer in
/// data) to `to_ea`; a value of the revision it was read at. Equal when made
/// at the same place, to the same address, the same way, in the same
/// database. A call, as evidence (`evidence=[...]`): the call at
/// `from_ea` (its caller's C line); no other kind is cited alone (cite
/// `db.xrefs.to_ea(x.to_ea)`: what refers there).
#[pyclass(frozen, eq, hash, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Xref {
    db: Arc<Db>,
    /// Where it is made.
    #[pyo3(get)]
    from_ea: u64,
    /// What it refers to.
    #[pyo3(get)]
    to_ea: u64,
    kind: &'static str,
    function_entry: Option<u64>,
    /// A pointer's origin: `relocation` or `scan` (else `None`).
    #[pyo3(get)]
    pointer_origin: Option<&'static str>,
    /// A relocated pointer's relocation: `relative`, `absolute`,
    /// `glob_dat`, `jump_slot`, `base` or `rebase` (Mach-O).
    #[pyo3(get)]
    relocation: Option<&'static str>,
}

impl PartialEq for Xref {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.db, &other.db)
            && (self.from_ea, self.to_ea, self.kind, self.relocation)
                == (other.from_ea, other.to_ea, other.kind, other.relocation)
    }
}

impl Eq for Xref {}

impl Hash for Xref {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.db).hash(state);
        (self.from_ea, self.to_ea, self.kind, self.relocation).hash(state);
    }
}

#[pymethods]
impl Xref {
    fn __repr__(&self) -> String {
        format!(
            "Xref(from_ea={:#x}, to_ea={:#x}, kind={})",
            self.from_ea, self.to_ea, self.kind
        )
    }

    /// How it refers: an `XrefKind`.
    #[getter]
    fn kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        member(py, "XrefKind", self.kind)
    }

    /// The function making it (`None`: a pointer in data).
    #[getter]
    fn function(&self) -> Option<Function> {
        self.function_entry
            .map(|entry| Function::new(&self.db, entry))
    }

    /// Whether it is a call or a jump.
    #[getter]
    fn is_code(&self) -> bool {
        matches!(self.kind, "call" | "jump")
    }

    /// Whether it is a call.
    #[getter]
    fn is_call(&self) -> bool {
        self.kind == "call"
    }

    /// Whether it is a jump.
    #[getter]
    fn is_jump(&self) -> bool {
        self.kind == "jump"
    }

    /// Whether it reads.
    #[getter]
    fn is_read(&self) -> bool {
        self.kind == "read"
    }

    /// Whether it writes.
    #[getter]
    fn is_write(&self) -> bool {
        self.kind == "write"
    }

    /// What it is cited as: the call at `from_ea`, if it is a call.
    fn _cite(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        if self.kind != "call" {
            return Err(PyValueError::new_err(format!(
                "a {} reference is not cited alone, only a call is (the call at its site); \
                 cite db.xrefs.to_ea({:#x}) for what refers to {:#x}",
                self.kind, self.to_ea, self.to_ea
            )));
        }
        cited(py, &EvidenceRefData::Call { site: self.from_ea })
    }
}

/// `reference` of `database` as an [`Xref`].
pub(crate) fn xref(db: &Arc<Db>, database: &Engine<'_>, reference: &Reference) -> Xref {
    let (origin, relocation) = pointer_origin(reference.kind);
    Xref {
        db: Arc::clone(db),
        from_ea: reference.from,
        to_ea: reference.target,
        kind: kind_name(reference.kind),
        function_entry: reference
            .function
            .and_then(|id| database.function(id))
            .map(|f| f.entry),
        pointer_origin: origin,
        relocation,
    }
}

/// Whether `reference` is of one of `kinds` (`None`: any).
fn wanted(reference: &Reference, kinds: Option<&[String]>) -> bool {
    kinds.is_none_or(|kinds| kinds.iter().any(|k| k == kind_name(reference.kind)))
}

/// `binbun.XrefKind` members (or their values) as values.
fn kind_values(kinds: Option<&Bound<'_, PyAny>>) -> PyResult<Option<Vec<String>>> {
    let Some(kinds) = kinds.filter(|k| !k.is_none()) else {
        return Ok(None);
    };
    kinds
        .try_iter()?
        .map(|kind| {
            let kind = kind?;
            match kind.getattr("value") {
                Ok(value) => value.extract::<String>(),
                Err(_) => kind.extract::<String>(),
            }
        })
        .collect::<PyResult<Vec<String>>>()
        .map(Some)
}

/// The references to `ea` of `db`, of `kinds`: a `binbun.XrefsTo`, which
/// remembers `ea`.
pub(crate) fn to_ea(
    py: Python<'_>,
    db: &Arc<Db>,
    ea: u64,
    kinds: Option<&[String]>,
) -> PyResult<Py<PyAny>> {
    let session = db.analysed(py)?;
    let database = engine(py, &session)?;
    let references = py.detach(|| database.references());
    let found: Vec<Xref> = references
        .to(ea)
        .iter()
        .filter(|r| wanted(r, kinds))
        .map(|r| xref(db, database, r))
        .collect();
    Ok(py
        .import("binbun._results")?
        .getattr("XrefsTo")?
        .call1((ea, found))?
        .unbind())
}

/// The cross-references of a database (`binbun xrefs`): to an address,
/// made at one, within a range. Built once (the first call waits for them).
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Xrefs {
    db: Arc<Db>,
}

impl Xrefs {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }
}

#[pymethods]
impl Xrefs {
    /// The references to `ea`, of `kinds` (a set of `XrefKind`; `None`:
    /// all): a `binbun.XrefsTo` (a list that remembers `ea`, cited as
    /// what refers to it).
    #[pyo3(signature = (ea, *, kinds = None))]
    fn to_ea(
        &self,
        py: Python<'_>,
        ea: Address,
        kinds: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        to_ea(py, &self.db, ea.0, kind_values(kinds)?.as_deref())
    }

    /// The references made at `ea`, of `kinds`.
    #[pyo3(name = "from_ea", signature = (ea, *, kinds = None))]
    fn made_at(
        &self,
        py: Python<'_>,
        ea: Address,
        kinds: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<Xref>> {
        let kinds = kind_values(kinds)?;
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let references = py.detach(|| database.references());
        let mut made: Vec<&Reference> = references
            .all()
            .iter()
            .filter(|r| r.from == ea.0 && wanted(r, kinds.as_deref()))
            .collect();
        made.sort_by_key(|r| (r.target, kind_name(r.kind)));
        Ok(made
            .into_iter()
            .map(|r| xref(&self.db, database, r))
            .collect())
    }

    /// The references to any address in `start..end`.
    fn to_range(&self, py: Python<'_>, start: Address, end: Address) -> PyResult<Vec<Xref>> {
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let references = py.detach(|| database.references());
        Ok(references
            .within(start.0..end.0)
            .iter()
            .map(|r| xref(&self.db, database, r))
            .collect())
    }

    /// Where the calls to `ea` are made.
    fn calls_to_ea(&self, py: Python<'_>, ea: Address) -> PyResult<Vec<u64>> {
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let references = py.detach(|| database.references());
        Ok(references
            .to(ea.0)
            .iter()
            .filter(|r| r.kind == Kind::Call)
            .map(|r| r.from)
            .collect())
    }

    /// Every reference (or those to `ea`) in columns, no object per
    /// reference: an `XrefTable`.
    #[pyo3(signature = (*, ea = None))]
    fn table(&self, py: Python<'_>, ea: Option<Address>) -> PyResult<XrefTable> {
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let references = py.detach(|| database.references());
        let chosen = match ea {
            Some(Address(ea)) => references.to(ea),
            None => references.all(),
        };
        let mut table = XrefTable::default();
        for r in chosen {
            table.from_ea.push(r.from);
            table.to_ea.push(r.target);
            table.kind.push(kind_name(r.kind));
            table.function.push(
                r.function
                    .and_then(|id| database.function(id))
                    .map(|f| f.entry),
            );
        }
        Ok(table)
    }

    /// The functions that do not lift: only their calls and jumps are
    /// recovered.
    #[getter]
    fn unlifted(&self, py: Python<'_>) -> PyResult<Vec<Function>> {
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let references = py.detach(|| database.references());
        Ok(references
            .unlifted()
            .iter()
            .filter_map(|&id| database.function(id))
            .map(|f| Function::new(&self.db, f.entry))
            .collect())
    }
}

/// Cross-references in columns: `from_ea`, `to_ea`, `kind` (`XrefKind` values)
/// and `function` (entries, `None` for pointers in data), one row each.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug, Default)]
pub(crate) struct XrefTable {
    /// Where each is made.
    #[pyo3(get)]
    from_ea: Vec<u64>,
    /// What each refers to.
    #[pyo3(get)]
    to_ea: Vec<u64>,
    /// How each refers.
    #[pyo3(get)]
    kind: Vec<&'static str>,
    /// The entry of the function making each.
    #[pyo3(get)]
    function: Vec<Option<u64>>,
}

#[pymethods]
impl XrefTable {
    fn __len__(&self) -> usize {
        self.from_ea.len()
    }
}
