//! `binbun.x86`: the x86 decoder (16, 32 and 64-bit, XED-exact) without a
//! database. An [`Instruction`] is bound to its address and keeps its
//! bytes; what it says (operands, flags, control flow, text, tokens) is
//! what the C API says of the same bytes.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

use binbun_capi::x86::{
    X86FlagEffect, X86Operand, condition, decode_mode, encoding, failure, write_tokens,
};
use binbun_capi::{Branch as CBranch, TEXT_DEFAULT};
use binbun_isa::Instruction as _;
use binbun_x86::{
    Instruction as Decoded, MAX_LENGTH, Mode, Register, decode as decode_bytes, decode_flow,
    decode_length as length_of,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule, PyString, PyTuple};

use crate::database::Address;
use crate::disasm::{Branch, Code, Enums, Invalid, Sweep, Token, Tokens, decode_error, hex};

/// `BINBUN_X86_MODE_BITS64`.
const BITS64: u32 = 5;

/// The mode numbered `mode`; `ValueError` if it is none.
fn mode_of(mode: u32) -> PyResult<Mode> {
    decode_mode(mode).map_err(|_| PyValueError::new_err(format!("{mode} is no x86 mode")))
}

/// One x86 instruction at its address: what it is (`mnemonic`, `form`,
/// `category`, `extension`, `isa_set`, `encoding`), its `operands`, what
/// it does to the `flags` and to the flow of control (`branch`), and its
/// text (Intel syntax as XED writes it) plain or as tokens. A value:
/// equal when the same bytes are decoded at the same address in the same
/// mode.
#[pyclass(frozen, eq, hash, module = "binbun.x86")]
#[derive(Debug)]
pub(crate) struct Instruction {
    decoded: Decoded,
    pub(crate) address: u64,
    mode: u32,
    bytes: [u8; MAX_LENGTH],
}

impl Instruction {
    pub(crate) fn new(decoded: Decoded, address: u64, mode: u32, code: &[u8]) -> Self {
        let mut bytes = [0; MAX_LENGTH];
        let length = decoded.len();
        if let (Some(to), Some(from)) = (bytes.get_mut(..length), code.get(..length)) {
            to.copy_from_slice(from);
        }
        Self {
            decoded,
            address,
            mode,
            bytes,
        }
    }

    fn code(&self) -> &[u8] {
        self.bytes.get(..self.decoded.len()).unwrap_or_default()
    }

    fn text_of(&self) -> String {
        self.decoded.intel(self.address).to_string()
    }
}

impl PartialEq for Instruction {
    fn eq(&self, other: &Self) -> bool {
        (self.address, self.mode, self.code()) == (other.address, other.mode, other.code())
    }
}

impl Eq for Instruction {}

impl Hash for Instruction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.address, self.mode, self.code()).hash(state);
    }
}

/// Whether `options` are the only ones x86 text has: none.
fn no_options(options: u32) -> PyResult<()> {
    if options == TEXT_DEFAULT {
        Ok(())
    } else {
        Err(PyValueError::new_err(format!(
            "x86 text has no options (got {options})"
        )))
    }
}

#[pymethods]
impl Instruction {
    /// Its address.
    #[getter]
    const fn address(&self) -> u64 {
        self.address
    }

    /// Its length in bytes, 1 to 15.
    #[getter]
    fn length(&self) -> usize {
        self.decoded.len()
    }

    fn __len__(&self) -> usize {
        self.decoded.len()
    }

    /// Its bytes.
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.code())
    }

    /// The mode it was decoded in: a `Mode`.
    #[getter]
    fn mode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::X86.member(py, "Mode", self.mode)
    }

    /// The mnemonic, XED's iclass in lower case (`add`, `call_near`,
    /// `rep_movsb`), as every mnemonic binbun gives is.
    #[getter]
    fn mnemonic<'py>(&self, py: Python<'py>) -> Bound<'py, PyString> {
        let name = self.decoded.mnemonic().as_str();
        let mut lower = [0u8; 64];
        match lower.get_mut(..name.len()) {
            Some(to) => {
                to.copy_from_slice(name.as_bytes());
                to.make_ascii_lowercase();
                PyString::new(py, std::str::from_utf8(to).unwrap_or(name))
            }
            None => PyString::new(py, &name.to_ascii_lowercase()),
        }
    }

    /// The form, XED's iform: the mnemonic with its operand types
    /// (`ADD_GPRv_GPRv_01`).
    #[getter]
    fn form(&self) -> &'static str {
        self.decoded.form().as_str()
    }

    /// The category (`BINARY`, `COND_BR`, `CALL`).
    #[getter]
    fn category(&self) -> &'static str {
        self.decoded.category().as_str()
    }

    /// The ISA extension (`BASE`, `AVX2`).
    #[getter]
    fn extension(&self) -> &'static str {
        self.decoded.extension().as_str()
    }

    /// The feature set it needs (`I86`, `AVX2`).
    #[getter]
    fn isa_set(&self) -> &'static str {
        self.decoded.isa_set().as_str()
    }

    /// How it is encoded: an `Encoding`.
    #[getter]
    fn encoding<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::X86.member(py, "Encoding", encoding(self.decoded.encoding()))
    }

    /// The condition it tests (`Jcc`, `SETcc`, `CMOVcc`, `LOOP`): a
    /// `Condition`, `Condition.NONE` for none.
    #[getter]
    fn condition<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let number = self.decoded.condition().map_or(0, condition);
        Enums::X86.member(py, "Condition", number)
    }

    /// The effective operand width in bits: 8, 16, 32 or 64.
    #[getter]
    fn operand_width(&self) -> u32 {
        self.decoded.operand_width()
    }

    /// The effective address width in bits, 16, 32 or 64, or 0 for none.
    #[getter]
    fn address_width(&self) -> u32 {
        self.decoded.address_width()
    }

    /// The stack address width in bits: 16, 32 or 64.
    #[getter]
    fn stack_address_width(&self) -> u32 {
        self.decoded.stack_address_width()
    }

    /// What it does to the flow of control at its address: relative
    /// targets as addresses, a jump or call through `[rip+disp]` as a
    /// `POINTER` target.
    #[getter]
    fn branch(&self) -> Branch {
        Branch(CBranch::new(self.decoded.flow(self.address)))
    }

    /// The address a RIP-relative `lea` computes, else `None`.
    #[getter]
    fn computed_address(&self) -> Option<u64> {
        self.decoded.computed_address(self.address)
    }

    /// What it does to the flags (XED's flag records).
    #[getter]
    fn flags(&self) -> Flags {
        Flags(X86FlagEffect::of(&self.decoded))
    }

    /// Its operands in XED's order: those the text shows, then implied
    /// ones (the stack pointer, the flags).
    #[getter]
    fn operands<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        let decoded = &self.decoded;
        let operands = decoded.operands().enumerate().map(|(position, operand)| {
            let register = |r: u16| Register::from_raw(r).map(Register::name);
            let c = X86Operand::new(decoded, position, &operand);
            Operand {
                register: register(c.reg),
                segment: register(c.segment),
                base: register(c.base),
                index: register(c.index),
                field: operand.name.as_str(),
                c,
            }
        });
        PyTuple::new(py, operands)
    }

    /// Its text, as XED writes Intel syntax (`lock add dword ptr
    /// [rax+rbx*4-0x10], 0x5`; branch targets as addresses). x86 text has
    /// no options: anything but `TextOptions.DEFAULT` is a `ValueError`.
    #[pyo3(signature = (options = 0))]
    fn text(&self, options: u32) -> PyResult<String> {
        no_options(options)?;
        Ok(self.text_of())
    }

    /// Its text as tokens, each a span of `text()`.
    #[pyo3(signature = (options = 0))]
    fn tokens(&self, options: u32) -> PyResult<Vec<Token>> {
        no_options(options)?;
        let mut tokens = Tokens::default();
        write_tokens(&self.decoded, self.address, &mut tokens)
            .map_err(|_| PyValueError::new_err("the text is too long"))?;
        Ok(tokens.0)
    }

    fn __str__(&self) -> String {
        self.text_of()
    }

    fn __repr__(&self) -> String {
        format!(
            "<x86.Instruction {:#x} [{}] {}>",
            self.address,
            hex(self.code()),
            self.text_of()
        )
    }
}

/// One operand (`binbun_x86_operand`): what its value is (`kind`), which
/// decoder field holds it (`field`), whether the text shows it
/// (`visibility`), how the instruction accesses it (`action`, `access`),
/// its width in `bits`, and the value: `register`; a memory operand's
/// `segment`, `base`, `index`, `scale`, `displacement` and `memory_size`;
/// an immediate's `value` and `signed_immediate`; a relative branch's
/// `displacement`. Fields a kind has not are 0 or `None`.
#[pyclass(frozen, eq, hash, module = "binbun.x86")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Operand {
    c: X86Operand,
    field: &'static str,
    /// A register operand's register (`rax`, `st(0)`), else `None`.
    #[pyo3(get)]
    register: Option<&'static str>,
    /// A memory operand's segment register as XED reports it (outside
    /// 64-bit mode the segment used, in 64-bit mode only an `fs` or `gs`
    /// override), else `None`.
    #[pyo3(get)]
    segment: Option<&'static str>,
    /// A memory operand's base register, else `None`.
    #[pyo3(get)]
    base: Option<&'static str>,
    /// A memory operand's index register, else `None`.
    #[pyo3(get)]
    index: Option<&'static str>,
}

#[pymethods]
impl Operand {
    /// What its value is: an `OperandKind`.
    #[getter]
    fn kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::X86.member(py, "OperandKind", self.c.kind)
    }

    /// Which decoder field holds it: an `OperandField` (XED's operand
    /// names, `REG0`, `MEM0`, `IMM0`, `RELBR`).
    #[getter]
    fn field<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::X86.member(py, "OperandField", self.c.field)
    }

    /// Whether the text shows it: a `Visibility`.
    #[getter]
    fn visibility<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::X86.member(py, "Visibility", self.c.visibility)
    }

    /// How the instruction accesses it: an `Action`.
    #[getter]
    fn action<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::X86.member(py, "Action", self.c.action)
    }

    /// Whether it may be read, may be written: a `binbun.Access`.
    #[getter]
    fn access<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Shared.member(py, "Access", self.c.access)
    }

    /// Its width in bits.
    #[getter]
    const fn bits(&self) -> u32 {
        self.c.bits
    }

    /// A memory operand's index multiplier (1, 2, 4 or 8), 0 without a
    /// SIB byte.
    #[getter]
    const fn scale(&self) -> u8 {
        self.c.scale
    }

    /// A memory operand's displacement, or a relative branch's
    /// displacement from the next instruction.
    #[getter]
    const fn displacement(&self) -> i64 {
        self.c.displacement
    }

    /// How many bytes a memory operand accesses; 0 for an address
    /// computation (`lea`).
    #[getter]
    const fn memory_size(&self) -> u32 {
        self.c.memory_size
    }

    /// An immediate's value (its bytes zero-extended), or an absolute
    /// branch address or far pointer offset.
    #[getter]
    const fn value(&self) -> u64 {
        self.c.value
    }

    /// Whether the instruction sign-extends an immediate.
    #[getter]
    const fn signed_immediate(&self) -> bool {
        self.c.signed_immediate
    }

    fn __repr__(&self) -> String {
        let shown = match self.c.kind {
            1 => self.register.unwrap_or("-").to_owned(),
            2 => format!(
                "[{}{}{}*{}{:+#x}]",
                self.segment.map_or(String::new(), |s| format!("{s}:")),
                self.base.unwrap_or(""),
                self.index.map_or(String::new(), |i| format!("+{i}")),
                self.c.scale,
                self.c.displacement
            ),
            5 => format!("{:+#x}", self.c.displacement),
            _ => format!("{:#x}", self.c.value),
        };
        format!("<x86.Operand {} {shown}>", self.field)
    }
}

/// What an instruction does to the flags (`binbun_x86_flag_effect`), as
/// `Flag` bits: `read`, `written` (modified, set, cleared or left
/// undefined) and `undefined`; whether it `may_write` them and whether it
/// `must_write` them (a shift by 0 does not).
#[pyclass(frozen, eq, hash, module = "binbun.x86")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Flags(X86FlagEffect);

#[pymethods]
impl Flags {
    /// The flags read.
    #[getter]
    fn read<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::X86.member(py, "Flag", self.0.read)
    }

    /// The flags written.
    #[getter]
    fn written<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::X86.member(py, "Flag", self.0.written)
    }

    /// The flags left undefined.
    #[getter]
    fn undefined<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::X86.member(py, "Flag", self.0.undefined)
    }

    /// Whether the instruction may write flags.
    #[getter]
    const fn may_write(&self) -> bool {
        self.0.may_write
    }

    /// Whether it always writes them.
    #[getter]
    const fn must_write(&self) -> bool {
        self.0.must_write
    }

    fn __repr__(&self) -> String {
        format!(
            "<x86.Flags read={:#x} written={:#x} undefined={:#x}>",
            self.0.read, self.0.written, self.0.undefined
        )
    }
}

/// Decodes the instruction at the start of `data` (`bytes`, `bytearray`,
/// `memoryview`...), which is at `address`, in `mode`. `DecodeError` if
/// the bytes are no instruction (its `status` says why:
/// `Status.TRUNCATED` if they end before it does).
#[pyfunction]
#[pyo3(signature = (data, address = Address(0), mode = BITS64))]
fn decode(
    py: Python<'_>,
    data: &Bound<'_, PyAny>,
    address: Address,
    mode: u32,
) -> PyResult<Instruction> {
    let code = Code::new(data)?;
    let bytes = code.as_slice(py);
    decode_bytes(bytes, mode_of(mode)?)
        .map(|decoded| Instruction::new(decoded, address.0, mode, bytes))
        .map_err(|error| decode_error(py, failure(error), address.0))
}

/// The length of the instruction at the start of `data` in `mode`:
/// XED's length decoder alone, which decodes prefixes and opcode maps but
/// does not check which instructions exist, so it accepts some bytes
/// `decode` rejects. `DecodeError` if it finds no length.
#[pyfunction]
#[pyo3(signature = (data, mode = BITS64))]
fn decode_length(py: Python<'_>, data: &Bound<'_, PyAny>, mode: u32) -> PyResult<usize> {
    let code = Code::new(data)?;
    length_of(code.as_slice(py), mode_of(mode)?)
        .map_err(|error| decode_error(py, failure(error), 0))
}

/// A linear sweep of `data`, which is at `address`, in `mode`, in columns
/// (`binbun.Sweep`): what `Decoder` yields, without an object per
/// instruction, decoded with the GIL released.
#[pyfunction]
#[pyo3(signature = (data, address = Address(0), mode = BITS64))]
fn sweep(py: Python<'_>, data: &Bound<'_, PyAny>, address: Address, mode: u32) -> PyResult<Sweep> {
    let code = Code::new(data)?;
    let mode = mode_of(mode)?;
    let bytes = code.as_slice(py);
    Ok(py.detach(|| {
        let mut sweep = Sweep::default();
        let mut offset = 0;
        while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
            let at = address.0.wrapping_add(offset as u64);
            match decode_flow(rest, mode, at) {
                Ok(step) => {
                    sweep.instruction(at, step.len, &CBranch::new(step.flow));
                    offset += step.len;
                }
                Err(error) => {
                    sweep.invalid(at, 1, failure(error));
                    offset += 1;
                }
            }
        }
        sweep
    }))
}

/// A linear sweep over a buffer of code, which is at `address`, in
/// `mode`: an iterator of `Instruction`s and, where bytes are no
/// instruction, `binbun.Invalid` steps of one byte, so that a sweep over
/// data resynchronises (as `binbun_x86_decoder_next`). `offset` is where
/// the next instruction is in the buffer; set it to continue elsewhere.
#[pyclass(frozen, module = "binbun.x86")]
#[derive(Debug)]
pub(crate) struct Decoder {
    code: Code,
    mode: Mode,
    mode_id: u32,
    start: u64,
    offset: AtomicUsize,
}

#[pymethods]
impl Decoder {
    #[new]
    #[pyo3(signature = (data, address = Address(0), mode = BITS64))]
    fn new(data: &Bound<'_, PyAny>, address: Address, mode: u32) -> PyResult<Self> {
        Ok(Self {
            code: Code::new(data)?,
            mode: mode_of(mode)?,
            mode_id: mode,
            start: address.0,
            offset: AtomicUsize::new(0),
        })
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
        Ok(Some(match decode_bytes(rest, self.mode) {
            Ok(decoded) => {
                self.offset.store(offset + decoded.len(), Ordering::Relaxed);
                Py::new(py, Instruction::new(decoded, at, self.mode_id, rest))?.into_any()
            }
            Err(error) => {
                self.offset.store(offset + 1, Ordering::Relaxed);
                let byte = rest.get(..1).unwrap_or_default().to_vec();
                Py::new(py, Invalid::new(at, failure(error), byte))?.into_any()
            }
        }))
    }

    fn __repr__(&self) -> String {
        format!("<x86.Decoder at {:#x}>", self.address())
    }
}

/// `binbun._native.x86`, re-exported by `binbun.x86`.
pub(crate) fn module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new(py, "x86")?;
    m.add("MAX_LENGTH", MAX_LENGTH)?;
    m.add_function(wrap_pyfunction!(decode, &m)?)?;
    m.add_function(wrap_pyfunction!(decode_length, &m)?)?;
    m.add_function(wrap_pyfunction!(sweep, &m)?)?;
    m.add_class::<Decoder>()?;
    m.add_class::<Instruction>()?;
    m.add_class::<Operand>()?;
    m.add_class::<Flags>()?;
    Ok(m)
}
