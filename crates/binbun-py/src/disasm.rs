//! What the decoders (`binbun.x86`, `binbun.aarch64`) share. Their
//! vocabulary is the C API's (`binbun-capi`, `binbun/disasm.h`):
//! the same statuses, branches, tokens and numbers behind every enum,
//! computed by the same code. Values are kept as the C API's numbers and
//! become the Python enums (`binbun._enums`, `binbun.x86`,
//! `binbun.aarch64`) when read.

use binbun_capi::{Branch as CBranch, NO_OPERAND, Status, TokenKind, TokenSink};
use binbun_isa::Flow;
use pyo3::buffer::PyBuffer;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyBytes, PyList, PyModule};

use crate::errors::class;

/// The Python modules holding the enums the decoders' numbers become.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Enums {
    /// `binbun._enums`: `Status`, `BranchKind`, `TokenKind`, ...
    Shared,
    /// `binbun.x86`.
    X86,
    /// `binbun.aarch64`.
    Aarch64,
}

impl Enums {
    /// The module, imported once.
    fn module(self, py: Python<'_>) -> PyResult<&Bound<'_, PyModule>> {
        static SHARED: PyOnceLock<Py<PyModule>> = PyOnceLock::new();
        static X86: PyOnceLock<Py<PyModule>> = PyOnceLock::new();
        static AARCH64: PyOnceLock<Py<PyModule>> = PyOnceLock::new();
        let (cell, name) = match self {
            Self::Shared => (&SHARED, "binbun._enums"),
            Self::X86 => (&X86, "binbun.x86"),
            Self::Aarch64 => (&AARCH64, "binbun.aarch64"),
        };
        cell.get_or_try_init(py, || Ok(py.import(name)?.unbind()))
            .map(|module| module.bind(py))
    }

    /// Member `value` of enum `name`.
    pub(crate) fn member<'py, V>(
        self,
        py: Python<'py>,
        name: &str,
        value: V,
    ) -> PyResult<Bound<'py, PyAny>>
    where
        V: IntoPyObject<'py>,
    {
        self.module(py)?.getattr(name)?.call1((value,))
    }
}

/// `binbun.Status` member `status`.
pub(crate) fn status(py: Python<'_>, status: Status) -> PyResult<Bound<'_, PyAny>> {
    Enums::Shared.member(py, "Status", status as i32)
}

/// `binbun.DecodeError` for bytes at `address` that are no instruction.
pub(crate) fn decode_error(py: Python<'_>, failure: Status, address: u64) -> PyErr {
    let message = format!("{} at {address:#x}", failure.description());
    let error = class(py, "binbun._errors", "DecodeError")
        .and_then(|class| class.call1((message, status(py, failure)?, address)));
    match error {
        Ok(error) => PyErr::from_value(error),
        Err(error) => error,
    }
}

/// Bytes to decode: a `bytes` object, borrowed, or a copy of another
/// buffer (`bytearray`, `memoryview`, `mmap`...).
#[derive(Debug)]
pub(crate) enum Code {
    /// Borrowed: `bytes` cannot change.
    Bytes(Py<PyBytes>),
    /// Copied once: other buffers can.
    Copied(Vec<u8>),
}

impl Code {
    /// The bytes of `data`; `TypeError` if it is no buffer of bytes.
    pub(crate) fn new(data: &Bound<'_, PyAny>) -> PyResult<Self> {
        if let Ok(bytes) = data.cast::<PyBytes>() {
            return Ok(Self::Bytes(bytes.clone().unbind()));
        }
        let buffer = PyBuffer::<u8>::get(data)?;
        Ok(Self::Copied(buffer.to_vec(data.py())?))
    }

    /// The bytes.
    pub(crate) fn as_slice<'a>(&'a self, py: Python<'_>) -> &'a [u8] {
        match self {
            Self::Bytes(bytes) => bytes.as_bytes(py),
            Self::Copied(bytes) => bytes,
        }
    }
}

/// What an instruction does to the flow of control, as it would at its
/// address (`binbun_branch`): `kind`, whether it is `conditional`,
/// whether execution `falls_through` to the next instruction, and where
/// it goes (`target_kind`, `target`).
#[pyclass(frozen, eq, hash, module = "binbun._native")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Branch(pub(crate) CBranch);

#[pymethods]
impl Branch {
    /// How it transfers control: a `binbun.BranchKind`.
    #[getter]
    fn kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Shared.member(py, "BranchKind", self.0.kind)
    }

    /// Whether the jump or trap happens only when a condition holds.
    #[getter]
    const fn conditional(&self) -> bool {
        self.0.conditional
    }

    /// Whether execution can continue with the next instruction.
    #[getter]
    const fn falls_through(&self) -> bool {
        self.0.falls_through
    }

    /// Where it goes: a `binbun.TargetKind`.
    #[getter]
    fn target_kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Shared.member(py, "TargetKind", self.0.target_kind)
    }

    /// The target address (`ADDRESS`), the address of the pointer to it
    /// (`POINTER`) or the far offset (`FAR`); `None` for the others.
    #[getter]
    const fn target(&self) -> Option<u64> {
        target(&self.0)
    }

    /// The pointer's size in bytes, for a `POINTER` target; else 0.
    #[getter]
    const fn pointer_size(&self) -> u8 {
        self.0.pointer_size
    }

    /// The segment selector, for a `FAR` target; else 0.
    #[getter]
    const fn selector(&self) -> u16 {
        self.0.selector
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let kind = self.kind(py)?.getattr("name")?;
        let target = self.target_kind(py)?.getattr("name")?;
        let conditional = if self.0.conditional { "?" } else { "" };
        Ok(match self.target() {
            Some(address) => format!("<Branch {kind}{conditional} {target} {address:#x}>"),
            None => format!("<Branch {kind}{conditional} {target}>"),
        })
    }
}

/// The address `branch` names, if it names one.
pub(crate) const fn target(branch: &CBranch) -> Option<u64> {
    // binbun_target_kind: ADDRESS 1, POINTER 2, FAR 4.
    match branch.target_kind {
        1 | 2 | 4 => Some(branch.target),
        _ => None,
    }
}

/// One token of an instruction's text (`binbun_token`): its `kind`, the
/// operand it is part of (`None` for the mnemonic, prefixes, separators
/// and the whitespace between them), where it is in the text, the number
/// it stands for, and its `text`.
#[pyclass(frozen, eq, hash, module = "binbun._native")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Token {
    kind: u8,
    operand: u8,
    /// Where the token starts in the instruction's text.
    #[pyo3(get)]
    offset: usize,
    /// Its length.
    #[pyo3(get)]
    length: usize,
    /// What it stands for: an immediate's, an integer's, an address's or
    /// a displacement's value (two's complement when negative), a float's
    /// bits, an x86 register's number; 0 for the others.
    #[pyo3(get)]
    value: u64,
    /// Its text.
    #[pyo3(get)]
    text: String,
}

#[pymethods]
impl Token {
    /// What it is: a `binbun.TokenKind`.
    #[getter]
    fn kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Shared.member(py, "TokenKind", self.kind)
    }

    /// Which operand (an index into the instruction's `operands`) it is
    /// part of; `None` for none.
    #[getter]
    const fn operand(&self) -> Option<u8> {
        if self.operand == NO_OPERAND {
            None
        } else {
            Some(self.operand)
        }
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let kind = self.kind(py)?.getattr("name")?;
        Ok(format!("<Token {kind} {:?}>", self.text))
    }
}

/// An instruction's text and tokens, written by the C API's token
/// writers.
#[derive(Debug, Default)]
pub(crate) struct Tokens(pub(crate) Vec<Token>);

impl TokenSink for Tokens {
    fn push(&mut self, kind: TokenKind, operand: u8, text: &str, value: u64) {
        let offset = self.0.last().map_or(0, |last| last.offset + last.length);
        self.0.push(Token {
            kind: kind as u8,
            operand,
            offset,
            length: text.len(),
            value,
            text: text.to_owned(),
        });
    }
}

/// Bytes a decoder stepped over because they are no instruction: where
/// they are, why (`status`), and how many (1 on x86, where a sweep
/// resynchronises byte by byte; 4 on AArch64, fewer at the end of the
/// buffer).
#[pyclass(frozen, eq, hash, module = "binbun._native")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Invalid {
    /// The address of the first byte.
    #[pyo3(get)]
    pub(crate) address: u64,
    status: Status,
    bytes: Vec<u8>,
}

impl Invalid {
    pub(crate) const fn new(address: u64, status: Status, bytes: Vec<u8>) -> Self {
        Self {
            address,
            status,
            bytes,
        }
    }
}

#[pymethods]
impl Invalid {
    /// Why the bytes are no instruction: a `binbun.Status`.
    #[getter]
    fn status<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        status(py, self.status)
    }

    /// How many bytes the decoder stepped over.
    #[getter]
    fn length(&self) -> usize {
        self.bytes.len()
    }

    /// The bytes.
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.bytes)
    }

    fn __len__(&self) -> usize {
        self.bytes.len()
    }

    fn __repr__(&self) -> String {
        format!(
            "<Invalid {:#x}: {} ({})>",
            self.address,
            hex(&self.bytes),
            self.status.description()
        )
    }
}

/// `bytes` as hexadecimal pairs separated by spaces.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A linear sweep in columns, one entry per instruction or invalid step,
/// without an object per instruction: `addresses`, `lengths`, `statuses`
/// (0, `Status.OK`, for an instruction), `branch_kinds` and
/// `target_kinds` (`BranchKind`, `TargetKind` numbers), `targets` (as
/// `Branch.target`). Each read of a column makes a new list.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug, Default)]
pub(crate) struct Sweep {
    /// Each instruction's address.
    #[pyo3(get)]
    addresses: Vec<u64>,
    lengths: Vec<u8>,
    /// Each one's status: 0 for an instruction, else why it is none.
    #[pyo3(get)]
    statuses: Vec<i32>,
    branch_kinds: Vec<u8>,
    target_kinds: Vec<u8>,
    /// Each one's target, as `Branch.target`.
    #[pyo3(get)]
    targets: Vec<Option<u64>>,
}

impl Sweep {
    /// An instruction of `length` bytes at `address`, branching as
    /// `branch`.
    pub(crate) fn instruction(&mut self, address: u64, length: usize, branch: &CBranch) {
        self.push(address, length, Status::Ok, branch);
    }

    /// `length` bytes at `address` that are no instruction, for `status`.
    pub(crate) fn invalid(&mut self, address: u64, length: usize, status: Status) {
        self.push(address, length, status, &CBranch::new(Flow::Next));
    }

    fn push(&mut self, address: u64, length: usize, status: Status, branch: &CBranch) {
        self.addresses.push(address);
        self.lengths.push(u8::try_from(length).unwrap_or(u8::MAX));
        self.statuses.push(status as i32);
        if status == Status::Ok {
            self.branch_kinds.push(branch.kind);
            self.target_kinds.push(branch.target_kind);
            self.targets.push(target(branch));
        } else {
            self.branch_kinds.push(0);
            self.target_kinds.push(0);
            self.targets.push(None);
        }
    }
}

#[pymethods]
impl Sweep {
    /// Each one's length in bytes.
    #[getter]
    fn lengths<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        PyList::new(py, self.lengths.iter().copied())
    }

    /// Each one's `BranchKind` number (0 for an invalid step).
    #[getter]
    fn branch_kinds<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        PyList::new(py, self.branch_kinds.iter().copied())
    }

    /// Each one's `TargetKind` number.
    #[getter]
    fn target_kinds<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        PyList::new(py, self.target_kinds.iter().copied())
    }

    fn __len__(&self) -> usize {
        self.addresses.len()
    }

    fn __repr__(&self) -> String {
        let invalid = self.statuses.iter().filter(|&&s| s != 0).count();
        format!(
            "<Sweep {} instructions, {invalid} invalid>",
            self.addresses.len() - invalid
        )
    }
}
