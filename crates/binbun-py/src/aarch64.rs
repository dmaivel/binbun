//! `binbun.aarch64`: the A64 decoder (every A64 encoding of the 2026-09
//! release of Arm's A-profile specification, LLVM-exact text) without a
//! database. An [`Instruction`]
//! is bound to its address; what it says (operands with their access,
//! flags, memory access, implicit registers, control flow, text, tokens)
//! is what the C API says of the same word.

use std::sync::atomic::{AtomicUsize, Ordering};

use binbun_aarch64::operand::{
    Operand as Decoded, Register as DecodedRegister, RegisterList as DecodedList,
};
use binbun_aarch64::{Instruction as Word, LabelStyle, decode as decode_one, decode_bytes};
use binbun_capi::Branch as CBranch;
use binbun_capi::aarch64::{
    A64Condition, A64Extend, A64FlagEffect, A64Immediate, A64IndexedRegister, A64Label, A64Memory,
    A64MemoryAccess, A64Named, A64Operand, A64Register, A64RegisterList, A64Shift, A64Za,
    A64ZaList, LENGTH, failure, style, write_tokens,
};
use binbun_isa::Instruction as _;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule, PyTuple};

use crate::database::Address;
use crate::disasm::{Branch, Code, Enums, Invalid, Sweep, Token, Tokens, decode_error};

/// The label style `options` ask for; `ValueError` for unknown options.
fn style_of(options: u32) -> PyResult<LabelStyle> {
    style(options).ok_or_else(|| PyValueError::new_err(format!("unknown text options {options}")))
}

/// One A64 instruction at its address: its `word`, the `encoding` it is
/// an instance of (Arm's name), its `mnemonic` after alias selection, its
/// `operands` (each with its access), what it does to the `flags`, the
/// memory access it makes, the registers it uses without naming them,
/// what it does to the flow of control (`branch`), and its text (as LLVM
/// writes it) plain or as tokens. A value: equal when the same word is
/// decoded at the same address.
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Instruction {
    decoded: Word,
    pub(crate) address: u64,
}

impl Instruction {
    pub(crate) const fn new(decoded: Word, address: u64) -> Self {
        Self { decoded, address }
    }

    fn text_of(&self, style: LabelStyle) -> String {
        self.decoded.display_with(self.address, style).to_string()
    }
}

#[pymethods]
impl Instruction {
    /// Its address.
    #[getter]
    const fn address(&self) -> u64 {
        self.address
    }

    /// The instruction word.
    #[getter]
    const fn word(&self) -> u32 {
        self.decoded.word()
    }

    /// Its length in bytes: 4.
    #[getter]
    fn length(&self) -> usize {
        self.decoded.len()
    }

    fn __len__(&self) -> usize {
        self.decoded.len()
    }

    /// Its bytes, little-endian.
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.decoded.word().to_le_bytes())
    }

    /// The encoding the word is an instance of, as Arm's specification
    /// names it (`ADD_64_addsub_shift`).
    #[getter]
    fn encoding(&self) -> &'static str {
        self.decoded.encoding().name()
    }

    /// The mnemonic of the encoding's own syntax (`ORR` for `mov x0, x1`).
    #[getter]
    fn encoding_mnemonic(&self) -> &'static str {
        self.decoded.encoding().mnemonic()
    }

    /// The architecture features the encoding needs (`FEAT_SVE`...).
    #[getter]
    fn features(&self) -> Vec<&'static str> {
        self.decoded.features().iter().map(|f| f.name()).collect()
    }

    /// The mnemonic as the text writes it, after alias selection (`mov`
    /// for `orr x0, xzr, x1`, `b.eq`).
    #[getter]
    fn mnemonic(&self) -> &'static str {
        self.decoded.mnemonic()
    }

    /// What it does to the flow of control at its address: `b`, `b.cond`,
    /// `cbz`, `tbz` and `bl` give their target; `br`, `blr` and their
    /// pointer-authenticating forms are `INDIRECT`.
    #[getter]
    fn branch(&self) -> Branch {
        Branch(CBranch::new(self.decoded.flow(self.address)))
    }

    /// The address an `adr` computes, else `None` (`adrp` computes a page,
    /// not a pointer).
    #[getter]
    fn computed_address(&self) -> Option<u64> {
        self.decoded.computed_address(self.address)
    }

    /// The condition it tests (`b.cond`, `csel`, `cbz`, `tbnz`), else
    /// `None`.
    #[getter]
    fn condition(&self) -> Option<Condition> {
        self.decoded
            .condition()
            .map(|condition| Condition(A64Condition::from(condition)))
    }

    /// The condition flags it reads and writes.
    #[getter]
    fn flags(&self) -> Flags {
        Flags(A64FlagEffect::of(self.decoded))
    }

    /// The memory access it makes through an operand, else `None`.
    #[getter]
    fn memory(&self) -> Option<MemoryAccess> {
        self.decoded
            .memory()
            .map(|access| MemoryAccess(A64MemoryAccess::from(access)))
    }

    /// The registers it reads without naming them (x30 of `ret`, x16 and
    /// x17 of `pacia1716`, FFR).
    #[getter]
    fn implicit_reads(&self) -> Vec<Register> {
        registers(self.decoded.implicit().reads)
    }

    /// The registers it writes without naming them (x30 of `bl`, FFR).
    #[getter]
    fn implicit_writes(&self) -> Vec<Register> {
        registers(self.decoded.implicit().writes)
    }

    /// Its operands, as the text writes them (after alias selection),
    /// each with how the instruction accesses it.
    #[getter]
    fn operands<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        let access = self.decoded.access();
        let operands = self
            .decoded
            .operands()
            .iter()
            .zip(access.iter())
            .map(|(&operand, &access)| {
                let c = A64Operand::new(&operand, access);
                Operand {
                    decoded: operand,
                    kind: c.kind,
                    access: c.access,
                    address: self.address,
                }
            })
            .collect::<Vec<_>>();
        PyTuple::new(py, operands)
    }

    /// Its text, as LLVM writes it: the mnemonic, a tab, the operands
    /// (`ldr\tx0, [x1, #0x8]`); labels as the addresses they name, or as
    /// offsets with `TextOptions.RELATIVE_LABELS`.
    #[pyo3(signature = (options = 0))]
    fn text(&self, options: u32) -> PyResult<String> {
        Ok(self.text_of(style_of(options)?))
    }

    /// Its text as tokens, each a span of `text(options)`.
    #[pyo3(signature = (options = 0))]
    fn tokens(&self, options: u32) -> PyResult<Vec<Token>> {
        let mut tokens = Tokens::default();
        write_tokens(self.decoded, self.address, style_of(options)?, &mut tokens)
            .map_err(|_| PyValueError::new_err("the text cannot be written"))?;
        Ok(tokens.0)
    }

    fn __str__(&self) -> String {
        self.text_of(LabelStyle::Absolute)
    }

    fn __repr__(&self) -> String {
        format!(
            "<aarch64.Instruction {:#x} [{:08x}] {}>",
            self.address,
            self.decoded.word(),
            self.text_of(LabelStyle::Absolute).replace('\t', " ")
        )
    }
}

/// `registers` as Python sees them.
fn registers(registers: &[DecodedRegister]) -> Vec<Register> {
    registers
        .iter()
        .map(|&register| Register(A64Register::new(register)))
        .collect()
}

/// A register, with what is written on it (`binbun_aarch64_register`):
/// its `register_class` and `number`, an arrangement (`lanes` elements of
/// `element`, or the element alone with 0 lanes), an element `index`, a
/// `predication`. `str()` writes it as the text does (`x0`, `sp`,
/// `v1.16b`, `z2.s[1]`, `p0/z`).
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Register(A64Register);

/// The letters of `binbun_aarch64_register_class`, from 1.
const CLASSES: [&str; 16] = [
    "w", "x", "w", "x", "b", "h", "s", "d", "q", "v", "z", "p", "pn", "zt", "c", "ffr",
];

/// The letters of `binbun_aarch64_element`, from 1.
const ELEMENTS: [&str; 5] = ["b", "h", "s", "d", "q"];

#[pymethods]
impl Register {
    /// Its class: a `RegisterClass`.
    #[getter]
    fn register_class<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "RegisterClass", self.0.class)
    }

    /// Its number; for general registers 31 is the zero register or the
    /// stack pointer, as the class says.
    #[getter]
    const fn number(&self) -> u8 {
        self.0.number
    }

    /// The arrangement's element count (`16` of `v0.16b`); 0 for none.
    #[getter]
    const fn lanes(&self) -> u8 {
        self.0.lanes
    }

    /// The arrangement's element size: an `Element`, `NONE` for none.
    #[getter]
    fn element<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "Element", self.0.element)
    }

    /// The element index (`1` of `v0.s[1]`), else `None`.
    #[getter]
    const fn index(&self) -> Option<u8> {
        if self.0.has_index {
            Some(self.0.index)
        } else {
            None
        }
    }

    /// The predicate qualifier: a `Predication`.
    #[getter]
    fn predication<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "Predication", self.0.predication)
    }

    fn __str__(&self) -> String {
        let r = &self.0;
        let class = CLASSES
            .get(usize::from(r.class).wrapping_sub(1))
            .copied()
            .unwrap_or("?");
        // W 1, X 2, WSP 3, XSP 4, FFR 16.
        let mut text = match (r.class, r.number) {
            (1, 31) => "wzr".to_owned(),
            (2, 31) => "xzr".to_owned(),
            (3, 31) => "wsp".to_owned(),
            (4, 31) => "sp".to_owned(),
            (16, _) => "ffr".to_owned(),
            _ => format!("{class}{}", r.number),
        };
        let element = ELEMENTS
            .get(usize::from(r.element).wrapping_sub(1))
            .copied();
        if let Some(element) = element {
            if r.lanes == 0 {
                text = format!("{text}.{element}");
            } else {
                text = format!("{text}.{}{element}", r.lanes);
            }
        }
        if r.has_index {
            text = format!("{text}[{}]", r.index);
        }
        match r.predication {
            1 => text + "/z",
            2 => text + "/m",
            _ => text,
        }
    }

    fn __repr__(&self) -> String {
        format!("<aarch64.Register {}>", self.__str__())
    }
}

/// One operand, as the text writes it: what it is (`kind`), how the
/// instruction accesses it (`access`: a memory operand's access is the
/// memory access; values are read), and its `value`: a `Register`
/// (`REGISTER`, `WRITEBACK`), `RegisterList`, `Immediate`, `Float`,
/// `Shift`, `Extend`, `Memory`, `Label`, `Cond`, `SystemRegister`,
/// `Named`, `Za`, `ZaList`, an `int` (`TABLE_SLICE`) or an
/// `IndexedRegister`.
#[pyclass(frozen, eq, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Operand {
    decoded: Decoded,
    kind: u8,
    access: u8,
    address: u64,
}

#[pymethods]
impl Operand {
    /// What it is: an `OperandKind`.
    #[getter]
    fn kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "OperandKind", self.kind)
    }

    /// Whether it is read, written: a `binbun.Access`.
    #[getter]
    fn access<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Shared.member(py, "Access", self.access)
    }

    /// What it holds, as its `kind` says.
    #[getter]
    fn value<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Ok(match self.decoded {
            Decoded::Register(register) | Decoded::Writeback(register) => {
                Bound::new(py, Register(A64Register::new(register)))?.into_any()
            }
            Decoded::List(list) => Bound::new(
                py,
                RegisterList {
                    c: A64RegisterList::from(list),
                    list,
                },
            )?
            .into_any(),
            Decoded::Immediate(immediate) => {
                Bound::new(py, Immediate(A64Immediate::from(immediate)))?.into_any()
            }
            Decoded::Float(float) => Bound::new(
                py,
                Float {
                    value: float.value,
                    exact: float.exact,
                },
            )?
            .into_any(),
            Decoded::Shift(shift) => Bound::new(py, Shift(A64Shift::from(shift)))?.into_any(),
            Decoded::Extend(extend) => Bound::new(py, Extend(A64Extend::from(extend)))?.into_any(),
            Decoded::Memory(memory) => Bound::new(py, Memory(A64Memory::from(memory)))?.into_any(),
            Decoded::Label(label) => Bound::new(
                py,
                Label {
                    c: A64Label::from(label),
                    target: label.target(self.address),
                },
            )?
            .into_any(),
            Decoded::Condition(condition) => Enums::Aarch64.member(py, "Cond", condition as u8)?,
            Decoded::SystemRegister(register) => Bound::new(
                py,
                SystemRegister {
                    name: register.name,
                    encoding: register.encoding,
                },
            )?
            .into_any(),
            Decoded::Named(named) => Bound::new(
                py,
                Named {
                    kind: A64Named::from(named).kind,
                    name: named.name,
                },
            )?
            .into_any(),
            Decoded::Za(za) => Bound::new(py, Za(A64Za::from(za)))?.into_any(),
            Decoded::ZaList(list) => Bound::new(py, ZaList(A64ZaList::from(list)))?.into_any(),
            Decoded::TableSlice(offset) => offset.into_pyobject(py)?.into_any(),
            Decoded::IndexedRegister(register) => {
                Bound::new(py, IndexedRegister(A64IndexedRegister::from(register)))?.into_any()
            }
        })
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let kind = self.kind(py)?.getattr("name")?;
        let value = self.value(py)?.str()?;
        Ok(format!("<aarch64.Operand {kind} {value}>"))
    }
}

/// A register list (`binbun_aarch64_register_list`): `count` registers
/// from `first`, numbers `stride` apart, written in `style`; `registers`
/// lists them.
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct RegisterList {
    c: A64RegisterList,
    list: DecodedList,
}

#[pymethods]
impl RegisterList {
    /// The first register, with the arrangement and index all share.
    #[getter]
    const fn first(&self) -> Register {
        Register(self.c.first)
    }

    /// How many registers.
    #[getter]
    const fn count(&self) -> u8 {
        self.c.count
    }

    /// The distance between their numbers.
    #[getter]
    const fn stride(&self) -> u8 {
        self.c.stride
    }

    /// How the list is written: a `ListStyle`.
    #[getter]
    fn style<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "ListStyle", self.c.style)
    }

    /// Every register of the list.
    #[getter]
    fn registers(&self) -> Vec<Register> {
        (0..self.list.registers())
            .map(|i| Register(A64Register::new(self.list.get(i))))
            .collect()
    }

    fn __repr__(&self) -> String {
        format!("<aarch64.RegisterList {}>", self.__str__())
    }

    fn __str__(&self) -> String {
        let names: Vec<String> = self.registers().iter().map(Register::__str__).collect();
        format!("{{ {} }}", names.join(", "))
    }
}

/// An immediate (`binbun_aarch64_immediate`): its `value` (two's
/// complement when `signed`), and how the text writes it (`radix`).
/// `int()` is the value, negative where signed.
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Immediate(A64Immediate);

#[pymethods]
impl Immediate {
    /// The value's bits (two's complement when `signed`).
    #[getter]
    const fn value(&self) -> u64 {
        self.0.value
    }

    /// Whether it is signed.
    #[getter]
    const fn signed(&self) -> bool {
        self.0.is_signed
    }

    /// How the text writes it: a `Radix`.
    #[getter]
    fn radix<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "Radix", self.0.radix)
    }

    fn __int__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        #[expect(
            clippy::cast_possible_wrap,
            reason = "a signed immediate is the two's complement of its bits"
        )]
        let signed = self.0.value as i64;
        if self.0.is_signed {
            Ok(signed.into_pyobject(py)?.into_any())
        } else {
            Ok(self.0.value.into_pyobject(py)?.into_any())
        }
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("<aarch64.Immediate {}>", self.__str__(py)?))
    }

    fn __str__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("#{}", self.__int__(py)?))
    }
}

/// A floating-point immediate: its `value`, and whether it is a constant
/// the encoding selects (`exact`, written shortest) rather than encodes.
#[pyclass(frozen, eq, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Float {
    /// The value.
    #[pyo3(get)]
    value: f64,
    /// Whether it is a constant the encoding selects.
    #[pyo3(get)]
    exact: bool,
}

#[pymethods]
impl Float {
    fn __repr__(&self) -> String {
        format!("<aarch64.Float {}>", self.__str__())
    }

    fn __str__(&self) -> String {
        format!("#{}", self.value)
    }
}

/// A shift of the operand before it (`binbun_aarch64_shift`): `kind` and
/// `amount`.
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Shift(A64Shift);

#[pymethods]
impl Shift {
    /// The kind: a `ShiftKind`.
    #[getter]
    fn kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "ShiftKind", self.0.kind)
    }

    /// The amount.
    #[getter]
    const fn amount(&self) -> u8 {
        self.0.amount
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("<aarch64.Shift {}>", self.__str__(py)?))
    }

    fn __str__(&self, py: Python<'_>) -> PyResult<String> {
        let kind: String = self.kind(py)?.getattr("name")?.extract()?;
        Ok(format!("{} #{}", kind.to_lowercase(), self.0.amount))
    }
}

/// An extend of the register before it (`binbun_aarch64_extend`): `kind`
/// and the shift `amount` (`None` where the text writes none).
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Extend(A64Extend);

#[pymethods]
impl Extend {
    /// The kind: an `ExtendKind`.
    #[getter]
    fn kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "ExtendKind", self.0.kind)
    }

    /// The shift amount, else `None`.
    #[getter]
    const fn amount(&self) -> Option<u8> {
        if self.0.has_amount {
            Some(self.0.amount)
        } else {
            None
        }
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("<aarch64.Extend {}>", self.__str__(py)?))
    }

    fn __str__(&self, py: Python<'_>) -> PyResult<String> {
        let kind: String = self.kind(py)?.getattr("name")?.extract()?;
        Ok(match self.amount() {
            Some(amount) => format!("{} #{amount}", kind.to_lowercase()),
            None => kind.to_lowercase(),
        })
    }
}

/// A memory operand (`binbun_aarch64_memory`): the `base` register, what
/// is added to it (`offset_kind`: an immediate `offset`, an `index`
/// register shifted or extended as `modifier` says, or `offset` vector
/// lengths), and the `writeback`.
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Memory(A64Memory);

#[pymethods]
impl Memory {
    /// The base register.
    #[getter]
    const fn base(&self) -> Register {
        Register(self.0.base)
    }

    /// What is added to the base: an `OffsetKind`.
    #[getter]
    fn offset_kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "OffsetKind", self.0.offset_kind)
    }

    /// The immediate offset, or the number of vector lengths; 0 for none.
    #[getter]
    const fn offset(&self) -> i64 {
        self.0.offset
    }

    /// Whether an immediate offset is signed.
    #[getter]
    const fn offset_signed(&self) -> bool {
        self.0.offset_signed
    }

    /// How the text writes an immediate offset: a `Radix`, else `None`.
    #[getter]
    fn offset_radix<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        (self.0.offset_radix != 0)
            .then(|| Enums::Aarch64.member(py, "Radix", self.0.offset_radix))
            .transpose()
    }

    /// The index register of a register offset, else `None`.
    #[getter]
    const fn index(&self) -> Option<Register> {
        // binbun_aarch64_offset_kind: REGISTER 2.
        if self.0.offset_kind == 2 {
            Some(Register(self.0.index))
        } else {
            None
        }
    }

    /// How the index is modified: a `Modifier`.
    #[getter]
    fn modifier<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "Modifier", self.0.modifier)
    }

    /// The modifier's kind: a `ShiftKind` or an `ExtendKind`, else `None`.
    #[getter]
    fn modifier_kind<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        // binbun_aarch64_modifier: SHIFT 1, EXTEND 2.
        let kind = match self.0.modifier {
            1 => "ShiftKind",
            2 => "ExtendKind",
            _ => return Ok(None),
        };
        Enums::Aarch64
            .member(py, kind, self.0.modifier_kind)
            .map(Some)
    }

    /// The modifier's amount, where the text writes one, else `None`.
    #[getter]
    const fn modifier_amount(&self) -> Option<u8> {
        if self.0.modifier_has_amount {
            Some(self.0.modifier_amount)
        } else {
            None
        }
    }

    /// Whether and when the base is written back: a `Writeback`.
    #[getter]
    fn writeback<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "Writeback", self.0.writeback)
    }

    fn __repr__(&self) -> String {
        format!("<aarch64.Memory {}>", self.__str__())
    }

    fn __str__(&self) -> String {
        let base = Register(self.0.base).__str__();
        let offset = self.0.offset;
        let sign = if offset < 0 { "-" } else { "" };
        let immediate = format!("#{sign}{:#x}", offset.unsigned_abs());
        // binbun_aarch64_offset_kind: IMMEDIATE 1, REGISTER 2, VECTOR_LENGTH 3;
        // binbun_aarch64_writeback: PRE 1, POST 2.
        match (self.0.offset_kind, self.0.writeback, self.index()) {
            (2, _, Some(index)) => format!("[{base}, {}]", index.__str__()),
            (1, 1, _) => format!("[{base}, {immediate}]!"),
            (1, 2, _) => format!("[{base}], {immediate}"),
            (1, _, _) if offset != 0 => format!("[{base}, {immediate}]"),
            (3, _, _) => format!("[{base}, #{offset}, mul vl]"),
            _ => format!("[{base}]"),
        }
    }
}

/// A PC-relative address (`binbun_aarch64_label`): `offset` from the
/// instruction or its 4 KiB page (`base`), the `target` it names, and how
/// relative text writes it (`radix`).
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Label {
    c: A64Label,
    /// The address it names.
    #[pyo3(get)]
    target: u64,
}

#[pymethods]
impl Label {
    /// The offset from the base.
    #[getter]
    const fn offset(&self) -> i64 {
        self.c.offset
    }

    /// What it is relative to: a `LabelBase`.
    #[getter]
    fn base<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "LabelBase", self.c.base)
    }

    /// How `TextOptions.RELATIVE_LABELS` writes it: a `Radix`.
    #[getter]
    fn radix<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "Radix", self.c.radix)
    }

    fn __repr__(&self) -> String {
        format!("<aarch64.Label {:#x}>", self.target)
    }

    fn __str__(&self) -> String {
        format!("{:#x}", self.target)
    }
}

/// A system register: its `name` for this access as LLVM writes it
/// (`TPIDR_EL0`; `None` where it has none) and its 16-bit `encoding`
/// (`op0:op1:CRn:CRm:op2`).
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SystemRegister {
    /// Its name, else `None`.
    #[pyo3(get)]
    name: Option<&'static str>,
    /// `op0:op1:CRn:CRm:op2`, `op0` in bits 15:14.
    #[pyo3(get)]
    encoding: u16,
}

#[pymethods]
impl SystemRegister {
    fn __repr__(&self) -> String {
        format!("<aarch64.SystemRegister {}>", self.__str__())
    }

    fn __str__(&self) -> String {
        self.name
            .map_or_else(|| format!("s{:#06x}", self.encoding), str::to_owned)
    }
}

/// A named operand: a prefetch operation, barrier option, BTI target,
/// PSTATE field, SVE pattern, system operation or keyword (`kind`), and
/// its `name` (lower case, `pldl1keep`, `ish`).
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Named {
    kind: u8,
    /// The name.
    #[pyo3(get)]
    name: &'static str,
}

#[pymethods]
impl Named {
    /// What it names: a `NameKind`.
    #[getter]
    fn kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "NameKind", self.kind)
    }

    fn __repr__(&self) -> String {
        format!("<aarch64.Named {}>", self.name)
    }

    fn __str__(&self) -> &'static str {
        self.name
    }
}

/// The SME array or a tile, whole or sliced (`binbun_aarch64_za`):
/// `tile` (`None`: the whole array), `element`, slice `direction`, and a
/// slice's index register `w<slice_index>`, `slice_offset`, `slice_last`
/// and vector `group` (2, 4, or 0).
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Za(A64Za);

#[pymethods]
impl Za {
    /// The tile, else `None` for the whole array.
    #[getter]
    const fn tile(&self) -> Option<u8> {
        if self.0.has_tile {
            Some(self.0.tile)
        } else {
            None
        }
    }

    /// The element size: an `Element`.
    #[getter]
    fn element<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "Element", self.0.element)
    }

    /// The slice direction: a `SliceDirection`.
    #[getter]
    fn direction<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "SliceDirection", self.0.direction)
    }

    /// The number of a slice's index register (`12` of `w12`), else
    /// `None` without a slice.
    #[getter]
    const fn slice_index(&self) -> Option<u8> {
        if self.0.has_slice {
            Some(self.0.slice_index)
        } else {
            None
        }
    }

    /// A slice's offset.
    #[getter]
    const fn slice_offset(&self) -> u8 {
        self.0.slice_offset
    }

    /// The last offset of a slice range, else `None`.
    #[getter]
    const fn slice_last(&self) -> Option<u8> {
        if self.0.has_last {
            Some(self.0.slice_last)
        } else {
            None
        }
    }

    /// A slice's vector group, 2 or 4, or 0.
    #[getter]
    const fn group(&self) -> u8 {
        self.0.group
    }

    fn __repr__(&self) -> String {
        format!("<aarch64.Za {}>", self.__str__())
    }

    fn __str__(&self) -> String {
        self.tile()
            .map_or_else(|| "za".to_owned(), |tile| format!("za{tile}"))
    }
}

/// A list of ZA tiles (`binbun_aarch64_za_list`): one slice (`za`) or the
/// 64-bit tiles in `tiles` (bit i for `za<i>.d`), as `kind` says.
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ZaList(A64ZaList);

#[pymethods]
impl ZaList {
    /// Which it is: a `ZaListKind`.
    #[getter]
    fn kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "ZaListKind", self.0.kind)
    }

    /// The 64-bit tiles, bit i for `za<i>.d`.
    #[getter]
    const fn tiles(&self) -> u8 {
        self.0.tiles
    }

    /// The slice, else `None`.
    #[getter]
    const fn za(&self) -> Option<Za> {
        // binbun_aarch64_za_list_kind: SLICE 1.
        if self.0.kind == 1 {
            Some(Za(self.0.za))
        } else {
            None
        }
    }

    fn __repr__(&self) -> String {
        format!("<aarch64.ZaList {}>", self.__str__())
    }

    fn __str__(&self) -> String {
        self.za().map_or_else(
            || format!("{{za tiles {:#x}}}", self.0.tiles),
            |za| za.__str__(),
        )
    }
}

/// A register selected by a general register plus an offset
/// (`p2.b[w12, 15]`): `register`, `index` and `offset`.
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct IndexedRegister(A64IndexedRegister);

#[pymethods]
impl IndexedRegister {
    /// The register selected from.
    #[getter]
    const fn register(&self) -> Register {
        Register(self.0.register)
    }

    /// The index register.
    #[getter]
    const fn index(&self) -> Register {
        Register(self.0.index)
    }

    /// The offset added to the index.
    #[getter]
    const fn offset(&self) -> u8 {
        self.0.offset
    }

    fn __repr__(&self) -> String {
        format!("<aarch64.IndexedRegister {}>", self.__str__())
    }

    fn __str__(&self) -> String {
        format!(
            "{}[{}, {}]",
            Register(self.0.register).__str__(),
            Register(self.0.index).__str__(),
            self.0.offset
        )
    }
}

/// The condition an instruction tests (`binbun_aarch64_condition`), as
/// `kind` says: the flags satisfy `cond` (`b.cond`, `csel`), `register`
/// is zero or not (`sense`: `cbz` true), bit `bit` of `register` is set
/// or clear (`sense`: `tbnz` true), or `register` compared with
/// `right_register` or `right_immediate` satisfies `cond`.
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Condition(A64Condition);

/// `binbun_aarch64_condition_kind`.
const FLAGS: u8 = 1;
/// `binbun_aarch64_condition_kind`.
const COMPARE: u8 = 4;

#[pymethods]
impl Condition {
    /// What is tested: a `ConditionKind`.
    #[getter]
    fn kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "ConditionKind", self.0.kind)
    }

    /// The condition, for `FLAGS` and `COMPARE` (as the encoding is: `cset
    /// w0, eq` tests `ne`); else `None`.
    #[getter]
    fn cond<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        matches!(self.0.kind, FLAGS | COMPARE)
            .then(|| Enums::Aarch64.member(py, "Cond", self.0.cond))
            .transpose()
    }

    /// `ZERO`: whether the test passes when the register is zero; `BIT`:
    /// when the bit is set.
    #[getter]
    const fn sense(&self) -> bool {
        self.0.sense
    }

    /// `BIT`: the bit's number.
    #[getter]
    const fn bit(&self) -> u8 {
        self.0.bit
    }

    /// The register tested, or the left one compared; `None` for `FLAGS`.
    #[getter]
    const fn register(&self) -> Option<Register> {
        if self.0.kind == FLAGS {
            None
        } else {
            Some(Register(self.0.register))
        }
    }

    /// `COMPARE`: what the register is compared with, a `CompareKind`;
    /// else `None`.
    #[getter]
    fn right_kind<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        (self.0.kind == COMPARE)
            .then(|| Enums::Aarch64.member(py, "CompareKind", self.0.right_kind))
            .transpose()
    }

    /// `COMPARE` with a register: the register; else `None`.
    #[getter]
    const fn right_register(&self) -> Option<Register> {
        // binbun_aarch64_compare_kind: REGISTER 1.
        if self.0.kind == COMPARE && self.0.right_kind == 1 {
            Some(Register(self.0.right_register))
        } else {
            None
        }
    }

    /// `COMPARE` with an immediate: the immediate; else `None`.
    #[getter]
    const fn right_immediate(&self) -> Option<i64> {
        // binbun_aarch64_compare_kind: IMMEDIATE 2.
        if self.0.kind == COMPARE && self.0.right_kind == 2 {
            Some(self.0.right_immediate)
        } else {
            None
        }
    }
}

/// The condition flags an instruction reads and writes, as `Flag` bits.
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Flags(A64FlagEffect);

#[pymethods]
impl Flags {
    /// The flags read (those the condition tests, the carry of `adc`...).
    #[getter]
    fn read<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "Flag", self.0.read)
    }

    /// The flags written.
    #[getter]
    fn written<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "Flag", self.0.written)
    }

    fn __repr__(&self) -> String {
        format!(
            "<aarch64.Flags read={:#x} written={:#x}>",
            self.0.read, self.0.written
        )
    }
}

/// The memory access an instruction makes through an operand: its `kind`
/// and `size` in bytes (0 where it depends on the vector length, the
/// implementation or a register).
#[pyclass(frozen, eq, hash, module = "binbun.aarch64")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct MemoryAccess(A64MemoryAccess);

#[pymethods]
impl MemoryAccess {
    /// What kind of access: a `MemoryKind`.
    #[getter]
    fn kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Enums::Aarch64.member(py, "MemoryKind", self.0.kind)
    }

    /// The bytes accessed in total; 0 where that is not fixed.
    #[getter]
    const fn size(&self) -> u32 {
        self.0.size
    }
}

/// Decodes the instruction word `word`, which is at `address`.
/// `DecodeError` if it is none (its `status` says why).
#[pyfunction]
#[pyo3(signature = (word, address = Address(0)))]
fn decode_word(py: Python<'_>, word: u32, address: Address) -> PyResult<Instruction> {
    decode_one(word)
        .map(|decoded| Instruction {
            decoded,
            address: address.0,
        })
        .map_err(|error| decode_error(py, failure(error), address.0))
}

/// Decodes the instruction at the start of `data` (little-endian; `bytes`,
/// `bytearray`, `memoryview`...), which is at `address`. `DecodeError` if
/// it is none (`Status.TRUNCATED` for fewer than 4 bytes).
#[pyfunction]
#[pyo3(signature = (data, address = Address(0)))]
fn decode(py: Python<'_>, data: &Bound<'_, PyAny>, address: Address) -> PyResult<Instruction> {
    let code = Code::new(data)?;
    decode_bytes(code.as_slice(py))
        .map(|decoded| Instruction {
            decoded,
            address: address.0,
        })
        .map_err(|error| decode_error(py, failure(error), address.0))
}

/// A linear sweep of `data`, which is at `address`, in columns
/// (`binbun.Sweep`): what `Decoder` yields, without an object per
/// instruction, decoded with the GIL released.
#[pyfunction]
#[pyo3(signature = (data, address = Address(0)))]
fn sweep(py: Python<'_>, data: &Bound<'_, PyAny>, address: Address) -> PyResult<Sweep> {
    let code = Code::new(data)?;
    let bytes = code.as_slice(py);
    Ok(py.detach(|| {
        let mut sweep = Sweep::default();
        for (index, chunk) in bytes.chunks(LENGTH).enumerate() {
            let at = address.0.wrapping_add((index * LENGTH) as u64);
            match decode_bytes(chunk) {
                Ok(decoded) => sweep.instruction(at, LENGTH, &CBranch::new(decoded.flow(at))),
                Err(error) => sweep.invalid(at, chunk.len(), failure(error)),
            }
        }
        sweep
    }))
}

/// A linear sweep over a buffer of code, which is at `address`: an
/// iterator of `Instruction`s and, for words that are none,
/// `binbun.Invalid` steps of 4 bytes (fewer at the end of the buffer:
/// `Status.TRUNCATED`), as `binbun_aarch64_decoder_next`. `offset` is
/// where the next instruction is in the buffer; set it to continue
/// elsewhere.
#[pyclass(frozen, module = "binbun.aarch64")]
#[derive(Debug)]
pub(crate) struct Decoder {
    code: Code,
    start: u64,
    offset: AtomicUsize,
}

#[pymethods]
impl Decoder {
    #[new]
    #[pyo3(signature = (data, address = Address(0)))]
    fn new(data: &Bound<'_, PyAny>, address: Address) -> PyResult<Self> {
        Ok(Self {
            code: Code::new(data)?,
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
        let chunk = rest.get(..LENGTH).unwrap_or(rest);
        self.offset.store(offset + chunk.len(), Ordering::Relaxed);
        Ok(Some(match decode_bytes(chunk) {
            Ok(decoded) => Py::new(
                py,
                Instruction {
                    decoded,
                    address: at,
                },
            )?
            .into_any(),
            Err(error) => Py::new(py, Invalid::new(at, failure(error), chunk.to_vec()))?.into_any(),
        }))
    }

    fn __repr__(&self) -> String {
        format!("<aarch64.Decoder at {:#x}>", self.address())
    }
}

/// `binbun._native.aarch64`, re-exported by `binbun.aarch64`.
pub(crate) fn module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new(py, "aarch64")?;
    m.add("LENGTH", LENGTH)?;
    m.add_function(wrap_pyfunction!(decode_word, &m)?)?;
    m.add_function(wrap_pyfunction!(decode, &m)?)?;
    m.add_function(wrap_pyfunction!(sweep, &m)?)?;
    m.add_class::<Decoder>()?;
    m.add_class::<Instruction>()?;
    m.add_class::<Operand>()?;
    m.add_class::<Register>()?;
    m.add_class::<RegisterList>()?;
    m.add_class::<Immediate>()?;
    m.add_class::<Float>()?;
    m.add_class::<Shift>()?;
    m.add_class::<Extend>()?;
    m.add_class::<Memory>()?;
    m.add_class::<Label>()?;
    m.add_class::<SystemRegister>()?;
    m.add_class::<Named>()?;
    m.add_class::<Za>()?;
    m.add_class::<ZaList>()?;
    m.add_class::<IndexedRegister>()?;
    m.add_class::<Condition>()?;
    m.add_class::<Flags>()?;
    m.add_class::<MemoryAccess>()?;
    Ok(m)
}
