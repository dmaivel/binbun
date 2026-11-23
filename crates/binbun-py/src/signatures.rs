//! Library signatures from Python:
//! `Function.name_source`, `Function.signature_match` (a [`SignatureMatch`]) and
//! `db.signatures` ([`Signatures`]: the packs read, the matches, a match
//! rejected).

use std::sync::Arc;

use binbun_protocol::Write;
use binbun_session::signatures::{NameSource, folders, label, read_folders};
use binbun_session::{Identified, Matched, Session};
use pyo3::prelude::*;

use crate::database::{Db, Entry};
use crate::errors::named;
use crate::functions::Function;
use crate::writes::write;

/// What a library signature says of a function: the pack, the library
/// function and how it matched.
#[pyclass(frozen, eq, module = "binbun._native")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignatureMatch {
    /// The pack and its revision (`musl-1.2.5@1`).
    #[pyo3(get)]
    pack: String,
    /// The library (`musl`).
    #[pyo3(get)]
    library: String,
    /// Its version.
    #[pyo3(get)]
    version: String,
    /// The library function's name.
    #[pyo3(get)]
    name: String,
    /// The object it comes from.
    #[pyo3(get)]
    object: String,
    /// How it matched: `exact` or `behaviour`.
    #[pyo3(get)]
    how: String,
    /// For a match by behaviour, the states that agreed.
    #[pyo3(get)]
    states: Option<u32>,
    /// For a match by behaviour, the candidates ruled out.
    #[pyo3(get)]
    ruled_out: Option<u32>,
    /// The library's prototype, as C, if the pack has one.
    #[pyo3(get)]
    prototype: Option<String>,
    /// Whether it returns: `False` where the type library declares it
    /// noreturn.
    #[pyo3(get)]
    returns: bool,
    /// Whether the user rejected the match.
    #[pyo3(get)]
    rejected: bool,
}

impl SignatureMatch {
    /// `identified` for Python.
    pub(crate) fn of(identified: Identified) -> Self {
        let (how, states, ruled_out) = match identified.how {
            Matched::Exact => ("exact", None, None),
            Matched::Behaviour { states, ruled_out } => {
                ("behaviour", Some(states), Some(ruled_out))
            }
        };
        Self {
            pack: identified.pack,
            library: identified.library,
            version: identified.version,
            name: identified.name,
            object: identified.object,
            how: how.to_owned(),
            states,
            ruled_out,
            prototype: identified.prototype,
            returns: !identified.no_return,
            rejected: identified.rejected,
        }
    }
}

#[pymethods]
impl SignatureMatch {
    fn __repr__(&self) -> String {
        format!(
            "SignatureMatch({:?}, {} {}, {}{})",
            self.name,
            self.library,
            self.version,
            self.how,
            if self.rejected { ", rejected" } else { "" }
        )
    }
}

/// Where the name of the function at `entry` comes from
/// ([`NameSource::name`]); `None` for binbun's own (`sub_…`).
pub(crate) fn name_source(session: &Session, entry: u64) -> Option<&'static str> {
    session.name_source(entry).as_ref().map(NameSource::name)
}

/// The library signatures of a database (`db.signatures`).
#[pyclass(frozen, module = "binbun._native")]
pub(crate) struct Signatures {
    db: Arc<Db>,
}

impl Signatures {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }
}

#[pymethods]
impl Signatures {
    /// The packs binbun reads (`library-version@revision`): the user's
    /// own, those installed with binbun, and `BINBUN_SIGNATURES`'s.
    #[getter]
    #[expect(
        clippy::unused_self,
        reason = "a property of db.signatures: the packs are binbun's, not the database's"
    )]
    fn packs(&self, py: Python<'_>) -> Vec<String> {
        py.detach(|| {
            let (packs, _) = read_folders(&folders());
            packs.iter().map(label).collect()
        })
    }

    /// Every match, by entry (those the user rejected too):
    /// `binbun.FunctionMatch(function, match)`s.
    fn matches<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        let session = self.db.analysed(py)?;
        session
            .signatures()
            .into_iter()
            .map(|(entry, identified)| {
                let function = Function::new(&self.db, entry);
                named(
                    py,
                    "FunctionMatch",
                    (function, SignatureMatch::of(identified)),
                )
            })
            .collect()
    }

    /// Rejects the match of `function` (a `Function` or its entry): its
    /// name and prototype as before, and no later run applies it again;
    /// undone, it is back.
    fn reject(&self, py: Python<'_>, function: Entry) -> PyResult<()> {
        write(py, &self.db, &Write::RejectSignature { entry: function.0 }).map(drop)
    }
}
