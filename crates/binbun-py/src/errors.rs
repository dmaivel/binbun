//! The exceptions binbun raises (`binbun._errors`, plain Python classes
//! so that each can also derive from the built-in it refines: an
//! `OpenError` is an `OSError`, an `InvalidAddressError` a `LookupError`),
//! raised from Rust by name, and the Python enums values cross as
//! (`binbun._enums`).

use binbun_protocol::{Fault, FaultKind};
use pyo3::call::PyCallArgs;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyModule, PyType};

/// The exception classes binbun raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Raise {
    /// The root of them all.
    Binbun,
    /// The file cannot be opened or read as an image.
    Open,
    /// The project cannot be read.
    Project,
    /// A read needs a stage the analysis did not reach.
    NotAnalysed,
    /// An address in no segment.
    InvalidAddress,
    /// No function starts there.
    NoFunction,
    /// No such variable.
    NoVariable,
    /// The analysis changed under an iterator or handle.
    Stale,
    /// A function handle's entry is no longer a function.
    FunctionGone,
    /// A function does not decompile.
    Decompile,
    /// A `timeout=` elapsed.
    Timeout,
    /// The question was cancelled.
    Cancelled,
    /// C refused (built with its span: [`fault`]).
    CDeclaration,
    /// A correction of recovery cannot apply.
    Correction,
    /// A transaction misused, or another thread's open.
    Transaction,
    /// A thread, post or suggestion cannot be written.
    Conversation,
    /// Writes refused.
    ReadOnly,
    /// The server lacks a capability.
    Capability,
    /// No database, or several and none chosen.
    Ambiguous,
    /// A malformed or unexpected message.
    Protocol,
    /// No protocol version both ends speak.
    Version,
    /// The connection failed or was lost.
    Connection,
    /// The server's directory or socket is another user's.
    Permission,
}

impl Raise {
    /// The class's name in `binbun._errors`.
    const fn name(self) -> &'static str {
        match self {
            Self::Binbun => "BinbunError",
            Self::Open => "OpenError",
            Self::Project => "ProjectError",
            Self::NotAnalysed => "NotAnalysedError",
            Self::InvalidAddress => "InvalidAddressError",
            Self::NoFunction => "NoFunctionError",
            Self::NoVariable => "NoVariableError",
            Self::Stale => "StaleError",
            Self::FunctionGone => "FunctionGoneError",
            Self::Decompile => "DecompileError",
            Self::Timeout => "TimeoutError",
            Self::Cancelled => "CancelledError",
            Self::CDeclaration => "CDeclarationError",
            Self::Correction => "CorrectionError",
            Self::Transaction => "TransactionError",
            Self::Conversation => "ConversationError",
            Self::ReadOnly => "ReadOnlyError",
            Self::Capability => "CapabilityError",
            Self::Ambiguous => "AmbiguousError",
            Self::Protocol => "ProtocolError",
            Self::Version => "VersionError",
            Self::Connection => "ConnectionError",
            Self::Permission => "PermissionError",
        }
    }

    /// The class raised for faults of `kind`.
    const fn of(kind: FaultKind) -> Self {
        match kind {
            FaultKind::Binbun => Self::Binbun,
            FaultKind::Open => Self::Open,
            FaultKind::Project => Self::Project,
            FaultKind::NotAnalysed => Self::NotAnalysed,
            FaultKind::InvalidAddress => Self::InvalidAddress,
            FaultKind::NoFunction => Self::NoFunction,
            FaultKind::NoVariable => Self::NoVariable,
            FaultKind::Stale => Self::Stale,
            FaultKind::FunctionGone => Self::FunctionGone,
            FaultKind::Decompile => Self::Decompile,
            FaultKind::CDeclaration => Self::CDeclaration,
            FaultKind::Correction => Self::Correction,
            FaultKind::Transaction => Self::Transaction,
            FaultKind::Conversation => Self::Conversation,
            FaultKind::ReadOnly => Self::ReadOnly,
            FaultKind::Timeout => Self::Timeout,
            FaultKind::Cancelled => Self::Cancelled,
            FaultKind::Capability => Self::Capability,
            FaultKind::Ambiguous => Self::Ambiguous,
            FaultKind::Protocol => Self::Protocol,
            FaultKind::Version => Self::Version,
            FaultKind::Connection => Self::Connection,
            FaultKind::Permission => Self::Permission,
        }
    }

    /// The exception, saying `message`.
    pub(crate) fn err(self, py: Python<'_>, message: impl Into<String>) -> PyErr {
        let message = message.into();
        match class(py, "binbun._errors", self.name()) {
            Ok(class) => PyErr::from_type(class, message),
            Err(error) => PyRuntimeError::new_err(format!("{message} (and {error})")),
        }
    }

    /// The exception, saying `message`, as a value (an item of
    /// `decompile_all`'s results).
    pub(crate) fn value<'py>(self, py: Python<'py>, message: &str) -> PyResult<Bound<'py, PyAny>> {
        class(py, "binbun._errors", self.name())?.call1((message,))
    }
}

/// `fault` as the exception its kind is: a `CDeclarationError` with the
/// C and the bytes of it at fault.
pub(crate) fn fault(py: Python<'_>, fault: Fault) -> PyErr {
    let raise = Raise::of(fault.kind);
    if raise != Raise::CDeclaration {
        return raise.err(py, fault.message);
    }
    let span = fault.span.map_or((0, 0), |span| (span.start, span.end));
    match class(py, "binbun._errors", raise.name())
        .and_then(|class| class.call1((fault.message.as_str(), span, fault.c.unwrap_or_default())))
    {
        Ok(error) => PyErr::from_value(error),
        Err(error) => error,
    }
}

/// Class `name` of module `module`.
pub(crate) fn class<'py>(
    py: Python<'py>,
    module: &str,
    name: &str,
) -> PyResult<Bound<'py, PyType>> {
    Ok(py.import(module)?.getattr(name)?.cast_into::<PyType>()?)
}

/// `binbun._enums`, imported once.
fn enums(py: Python<'_>) -> PyResult<&Bound<'_, PyModule>> {
    static ENUMS: PyOnceLock<Py<PyModule>> = PyOnceLock::new();
    ENUMS
        .get_or_try_init(py, || Ok(py.import("binbun._enums")?.unbind()))
        .map(|module| module.bind(py))
}

/// Member `value` of enum `name` of `binbun._enums`.
pub(crate) fn member<'py, V>(py: Python<'py>, name: &str, value: V) -> PyResult<Bound<'py, PyAny>>
where
    V: IntoPyObject<'py>,
{
    enums(py)?.getattr(name)?.call1((value,))
}

/// `binbun._results`, imported once.
fn results(py: Python<'_>) -> PyResult<&Bound<'_, PyModule>> {
    static RESULTS: PyOnceLock<Py<PyModule>> = PyOnceLock::new();
    RESULTS
        .get_or_try_init(py, || Ok(py.import("binbun._results")?.unbind()))
        .map(|module| module.bind(py))
}

/// Record `name` of `binbun._results` (a `NamedTuple`) of `fields`.
pub(crate) fn named<'py, A>(py: Python<'py>, name: &str, fields: A) -> PyResult<Bound<'py, PyAny>>
where
    A: PyCallArgs<'py>,
{
    results(py)?.getattr(name)?.call1(fields)
}
