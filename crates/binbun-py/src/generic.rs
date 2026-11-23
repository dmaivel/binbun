//! `binbun.Decoder`, `binbun.Instruction`, `binbun.disassemble`: one
//! decoder for both architectures (`binbun-disasm`), the architecture
//! chosen by the caller (`binbun.Arch`). An [`Instruction`] is bound to its
//! address and keeps its bytes; what it says (mnemonic, text, branch,
//! registers read and written) is what `binbun-disasm` says of them, and
//! `.x86`/`.aarch64` give the native instruction (`binbun.x86`,
//! `binbun.aarch64`) for everything else.

use std::sync::atomic::{AtomicUsize, Ordering};

use binbun_capi::aarch64::style;
use binbun_capi::{Branch as CBranch, Status, TEXT_DEFAULT};
use binbun_disasm::{Arch, DecodeError, Insn, Registers, decode};
use binbun_x86::{MAX_LENGTH, Mode};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};

use crate::aarch64::Instruction as A64Instruction;
use crate::database::Address;
use crate::disasm::{Branch, Code, Enums, Invalid, hex};
use crate::x86::Instruction as X86Instruction;

/// `BINBUN_X86_MODE_*` of `mode`.
const fn mode_number(mode: Mode) -> u32 {
    match mode {
        Mode::Real16 => 1,
        Mode::Real32 => 2,
        Mode::Bits16 => 3,
        Mode::Bits32 => 4,
        Mode::Bits64 => 5,
    }
}

/// The architecture `arch` (a `binbun.Arch` or its value) names, x86 in
/// `mode` (a `binbun.x86.Mode` number, 64-bit by default); `ValueError`
/// for an unknown architecture or mode, or a mode for AArch64.
fn arch_of(arch: &Bound<'_, PyAny>, mode: Option<u32>) -> PyResult<Arch> {
    let value = arch.getattr("value").unwrap_or_else(|_| arch.clone());
    let name = value
        .extract::<String>()
        .map_err(|_| PyValueError::new_err(format!("{arch} is no architecture (binbun.Arch)")))?;
    match (name.as_str(), mode) {
        ("x86", mode) => {
            let number = mode.unwrap_or(mode_number(Mode::Bits64));
            binbun_capi::x86::decode_mode(number)
                .map(Arch::X86)
                .map_err(|_| PyValueError::new_err(format!("{number} is no x86 mode")))
        }
        ("aarch64", None) => Ok(Arch::AArch64),
        ("aarch64", Some(_)) => Err(PyValueError::new_err(
            "AArch64 has no mode: pass mode only for x86",
        )),
        (other, _) => Err(PyValueError::new_err(format!(
            "no architecture {other:?} (x86, aarch64)"
        ))),
    }
}

/// The status of `error`, as the C API numbers it.
const fn failure(error: DecodeError) -> Status {
    match error {
        DecodeError::X86(error) => binbun_capi::x86::failure(error),
        DecodeError::AArch64(error) => binbun_capi::aarch64::failure(error),
    }
}

/// `registers` by name, as a tuple.
fn names<'py>(py: Python<'py>, registers: &Registers) -> PyResult<Bound<'py, PyTuple>> {
    PyTuple::new(py, registers.iter().map(ToString::to_string))
}

/// One instruction of either architecture at its address: the facts both
/// share (`arch`, `address`, `length`, `bytes`, `mnemonic`, `branch`,
/// `registers_read`, `registers_written`, `text()`), and the native
/// instruction (`x86` or `aarch64`, the other `None`) for the rest. A
/// value: equal when the same bytes are decoded at the same address for
/// the same architecture (and x86 mode).
#[pyclass(frozen, eq, hash, module = "binbun._native")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Instruction {
    arch: Arch,
    pub(crate) address: u64,
    bytes: [u8; MAX_LENGTH],
    length: u8,
}

impl Instruction {
    fn new(insn: &Insn<'_>) -> Self {
        let mut bytes = [0; MAX_LENGTH];
        let length = insn.len().min(MAX_LENGTH);
        if let (Some(to), Some(from)) = (bytes.get_mut(..length), insn.bytes().get(..length)) {
            to.copy_from_slice(from);
        }
        Self {
            arch: insn.arch(),
            address: insn.address(),
            bytes,
            length: u8::try_from(length).unwrap_or(0),
        }
    }

    fn code(&self) -> &[u8] {
        self.bytes
            .get(..usize::from(self.length))
            .unwrap_or_default()
    }

    /// The instruction, decoded again from its bytes (the bytes of an
    /// instruction always decode).
    fn insn(&self) -> PyResult<Insn<'_>> {
        decode(self.arch, self.code(), self.address)
            .map_err(|error| PyRuntimeError::new_err(format!("{error}")))
    }
}

#[pymethods]
impl Instruction {
    /// The architecture: a `binbun.Arch` (the x86 mode is `x86.mode`).
    #[getter]
    fn arch<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let value = match self.arch {
            Arch::X86(_) => "x86",
            Arch::AArch64 => "aarch64",
        };
        Enums::Shared.member(py, "Arch", value)
    }

    /// Its address.
    #[getter]
    const fn address(&self) -> u64 {
        self.address
    }

    /// Its length in bytes: 1 to 15 on x86, 4 on AArch64.
    #[getter]
    const fn length(&self) -> u8 {
        self.length
    }

    const fn __len__(&self) -> usize {
        self.length as usize
    }

    /// Its bytes (AArch64's word little-endian).
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.code())
    }

    /// The mnemonic its text writes, lower case: on x86 the word after any
    /// prefix words (`movsb` of `rep movsb`, where `x86.mnemonic` is XED's
    /// `REP_MOVSB`), on AArch64 after alias selection (`mov`, `b.eq`; Arm's
    /// is `aarch64.encoding_mnemonic`).
    #[getter]
    fn mnemonic(&self) -> PyResult<&'static str> {
        Ok(self.insn()?.mnemonic())
    }

    /// What it does to the flow of control at its address.
    #[getter]
    fn branch(&self) -> PyResult<Branch> {
        Ok(Branch(CBranch::new(self.insn()?.flow())))
    }

    /// The registers it may read, by name, each once: the decoders'
    /// operands (memory operands' address registers included) and
    /// implicit registers, the condition flags left out (`x86.flags`,
    /// `aarch64.flags`). Names are the architecture's (`al` and `rax`,
    /// `w0` and `x0` are different registers).
    #[getter]
    fn registers_read<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        names(py, &self.insn()?.registers_read())
    }

    /// The registers it may write, as `registers_read`.
    #[getter]
    fn registers_written<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        names(py, &self.insn()?.registers_written())
    }

    /// The x86 instruction (`binbun.x86.Instruction`), or `None` for
    /// AArch64.
    #[getter]
    fn x86(&self) -> PyResult<Option<X86Instruction>> {
        let insn = self.insn()?;
        Ok(match (self.arch, insn.as_x86()) {
            (Arch::X86(mode), Some(native)) => Some(X86Instruction::new(
                native.clone(),
                self.address,
                mode_number(mode),
                self.code(),
            )),
            _ => None,
        })
    }

    /// The AArch64 instruction (`binbun.aarch64.Instruction`), or `None`
    /// for x86.
    #[getter]
    fn aarch64(&self) -> PyResult<Option<A64Instruction>> {
        Ok(self
            .insn()?
            .as_aarch64()
            .map(|&native| A64Instruction::new(native, self.address)))
    }

    /// Its text, as the native decoder writes it (`x86.text`,
    /// `aarch64.text`): Intel syntax as XED writes it, or LLVM's (a tab
    /// after the mnemonic); branch targets as addresses, or on AArch64 as
    /// offsets with `TextOptions.RELATIVE_LABELS`. x86 text has no
    /// options: anything but `TextOptions.DEFAULT` is a `ValueError`.
    #[pyo3(signature = (options = 0))]
    fn text(&self, options: u32) -> PyResult<String> {
        let insn = self.insn()?;
        if options == TEXT_DEFAULT {
            return Ok(insn.to_string());
        }
        match insn.as_aarch64() {
            Some(native) => style(options)
                .map(|style| native.display_with(self.address, style).to_string())
                .ok_or_else(|| PyValueError::new_err(format!("unknown text options {options}"))),
            None => Err(PyValueError::new_err(format!(
                "x86 text has no options (got {options})"
            ))),
        }
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(self.insn()?.to_string())
    }

    fn __repr__(&self) -> PyResult<String> {
        let arch = match self.arch {
            Arch::X86(_) => "x86",
            Arch::AArch64 => "aarch64",
        };
        Ok(format!(
            "<Instruction {arch} {:#x} [{}] {}>",
            self.address,
            hex(self.code()),
            self.insn()?.to_string().replace('\t', " ")
        ))
    }
}

/// A linear sweep over a buffer of code, which is at `address`, for
/// `arch` (x86 in `mode`, 64-bit by default): an iterator of
/// `binbun.Instruction`s and, where bytes are no instruction,
/// `binbun.Invalid` steps as the native decoders take them (one byte on
/// x86, four on AArch64, fewer at the end of the buffer). `offset` is
/// where the next instruction is in the buffer; set it to continue
/// elsewhere.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Decoder {
    code: Code,
    arch: Arch,
    start: u64,
    offset: AtomicUsize,
}

impl Decoder {
    fn create(
        data: &Bound<'_, PyAny>,
        arch: &Bound<'_, PyAny>,
        address: Address,
        mode: Option<u32>,
    ) -> PyResult<Self> {
        Ok(Self {
            arch: arch_of(arch, mode)?,
            code: Code::new(data)?,
            start: address.0,
            offset: AtomicUsize::new(0),
        })
    }
}

#[pymethods]
impl Decoder {
    #[new]
    #[pyo3(signature = (data, *, arch, address = Address(0), mode = None))]
    fn new(
        data: &Bound<'_, PyAny>,
        arch: &Bound<'_, PyAny>,
        address: Address,
        mode: Option<u32>,
    ) -> PyResult<Self> {
        Self::create(data, arch, address, mode)
    }

    /// The architecture: a `binbun.Arch`.
    #[getter]
    fn arch<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let value = match self.arch {
            Arch::X86(_) => "x86",
            Arch::AArch64 => "aarch64",
        };
        Enums::Shared.member(py, "Arch", value)
    }

    /// Where the next instruction is in the buffer.
    #[getter]
    fn offset(&self) -> usize {
        self.offset.load(Ordering::Relaxed)
    }

    #[setter]
    fn set_offset(&self, offset: usize) {
        self.offset.store(offset, Ordering::Relaxed);
    }

    /// The address of the next instruction.
    #[getter]
    fn address(&self) -> u64 {
        self.start.wrapping_add(self.offset() as u64)
    }

    fn __iter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __next__(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        let offset = self.offset();
        let Some(rest) = self
            .code
            .as_slice(py)
            .get(offset..)
            .filter(|rest| !rest.is_empty())
        else {
            return Ok(None);
        };
        let at = self.address();
        Ok(Some(match decode(self.arch, rest, at) {
            Ok(insn) => {
                self.offset.store(offset + insn.len(), Ordering::Relaxed);
                Py::new(py, Instruction::new(&insn))?.into_any()
            }
            Err(error) => {
                let skipped = rest.get(..self.arch.invalid_step()).unwrap_or(rest);
                self.offset.store(offset + skipped.len(), Ordering::Relaxed);
                Py::new(py, Invalid::new(at, failure(error), skipped.to_vec()))?.into_any()
            }
        }))
    }

    fn __repr__(&self) -> String {
        let arch = match self.arch {
            Arch::X86(_) => "x86",
            Arch::AArch64 => "aarch64",
        };
        format!("<Decoder {arch} at {:#x}>", self.address())
    }
}

/// A linear sweep of `data` (`bytes`, `bytearray`, `memoryview`...), which
/// is at `address`, for `arch` (a `binbun.Arch`; x86 in `mode`, a
/// `binbun.x86.Mode`, 64-bit by default; no mode for AArch64): a
/// `binbun.Decoder`.
#[pyfunction]
#[pyo3(signature = (data, *, arch, address = Address(0), mode = None))]
pub(crate) fn disassemble(
    data: &Bound<'_, PyAny>,
    arch: &Bound<'_, PyAny>,
    address: Address,
    mode: Option<u32>,
) -> PyResult<Decoder> {
    Decoder::create(data, arch, address, mode)
}
