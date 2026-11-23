//! AArch64 operands (`binbun_aarch64_operand`): a kind and a union of the
//! values each kind has, every one with explicit padding so that the bytes
//! C reads are all written.

use std::fmt;

use binbun_aarch64::operand::{
    Arrangement, ElementSize, Extend, ExtendKind, Float, Immediate, IndexedRegister, Label,
    LabelBase, ListStyle, Memory, Modifier, NameKind, Named, Offset, Operand, Predication, Radix,
    Register, RegisterClass, RegisterList, Shift, ShiftKind, SliceDirection, SystemRegister,
    Writeback, Za, ZaList,
};
use binbun_aarch64::{Access, Instruction};

use super::{A64Instruction, read};
use crate::{ACCESS_READ, ACCESS_WRITE, Str, ffi};

/// A register with what is written on it (`binbun_aarch64_register`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64Register {
    /// Its class, a `binbun_aarch64_register_class`.
    pub class: u8,
    /// Its number; for general registers 31 is the zero register or the
    /// stack pointer, as the class says.
    pub number: u8,
    /// The number of elements of the arrangement (`16b`), 0 where only the
    /// element size is written or none.
    pub lanes: u8,
    /// The element size of the arrangement, a `binbun_aarch64_element`, 0
    /// for none.
    pub element: u8,
    /// The element index (`v0.s[1]`), where `has_index`.
    pub index: u8,
    /// Whether an element index is written.
    pub has_index: bool,
    /// The predicate qualifier, a `binbun_aarch64_predication`.
    pub predication: u8,
    /// Zero.
    pub reserved: u8,
}

const _: () = assert!(size_of::<A64Register>() == 8);

impl A64Register {
    /// `register` as C sees it.
    pub fn new(register: Register) -> Self {
        let (lanes, element) = register
            .arrangement
            .map_or((0, 0), |Arrangement { count, element }| {
                (count, element_size(element))
            });
        Self {
            class: register_class(register.class),
            number: register.number,
            lanes,
            element,
            index: register.index.unwrap_or(0),
            has_index: register.index.is_some(),
            predication: match register.predication {
                None => 0,
                Some(Predication::Zeroing) => 1,
                Some(Predication::Merging) => 2,
            },
            reserved: 0,
        }
    }
}

/// A list of vector registers (`binbun_aarch64_register_list`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64RegisterList {
    /// The first register, with the arrangement and index all share.
    pub first: A64Register,
    /// Number of registers.
    pub count: u8,
    /// Distance between register numbers, which wrap at the class's count.
    pub stride: u8,
    /// How it is written, a `binbun_aarch64_list_style`.
    pub style: u8,
    /// Zero.
    pub reserved: [u8; 5],
}

/// An immediate (`binbun_aarch64_immediate`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64Immediate {
    /// The value; two's complement when `is_signed`.
    pub value: u64,
    /// Whether it is signed.
    pub is_signed: bool,
    /// How it is written, a `binbun_aarch64_radix`.
    pub radix: u8,
    /// Zero.
    pub reserved: [u8; 6],
}

/// A floating-point immediate (`binbun_aarch64_float`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct A64Float {
    /// The value.
    pub value: f64,
    /// Whether it is a constant the encoding selects (written shortest)
    /// rather than encodes (written with eight decimals).
    pub exact: bool,
    /// Zero.
    pub reserved: [u8; 7],
}

/// A shift (`binbun_aarch64_shift`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64Shift {
    /// A `binbun_aarch64_shift_kind`.
    pub kind: u8,
    /// The amount.
    pub amount: u8,
    /// Zero.
    pub reserved: [u8; 6],
}

/// An extension (`binbun_aarch64_extend`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64Extend {
    /// A `binbun_aarch64_extend_kind`.
    pub kind: u8,
    /// The shift amount, where `has_amount`.
    pub amount: u8,
    /// Whether an amount is written.
    pub has_amount: bool,
    /// Zero.
    pub reserved: [u8; 5],
}

/// A memory operand (`binbun_aarch64_memory`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64Memory {
    /// The base register.
    pub base: A64Register,
    /// Register offset: the index register.
    pub index: A64Register,
    /// Immediate offset: the value (two's complement when `offset_signed`);
    /// vector-length offset: the multiple.
    pub offset: i64,
    /// What is added to the base, a `binbun_aarch64_offset_kind`.
    pub offset_kind: u8,
    /// Whether the base is written back, a `binbun_aarch64_writeback`.
    pub writeback: u8,
    /// Immediate offset: whether it is signed.
    pub offset_signed: bool,
    /// Immediate offset: how it is written, a `binbun_aarch64_radix`.
    pub offset_radix: u8,
    /// Register offset: what is applied to the index, a
    /// `binbun_aarch64_modifier`.
    pub modifier: u8,
    /// The shift or extend kind of the modifier.
    pub modifier_kind: u8,
    /// Its amount, where `modifier_has_amount`.
    pub modifier_amount: u8,
    /// Whether the modifier writes an amount.
    pub modifier_has_amount: bool,
}

/// A PC-relative address (`binbun_aarch64_label`): the offset from the
/// instruction's address, or from its 4 KiB page for `adrp`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64Label {
    /// The offset.
    pub offset: i64,
    /// What it is from, a `binbun_aarch64_label_base`.
    pub base: u8,
    /// How the offset is written with relative labels, a
    /// `binbun_aarch64_radix`.
    pub radix: u8,
    /// Zero.
    pub reserved: [u8; 6],
}

/// A system register (`binbun_aarch64_system_register`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A64SystemRegister {
    /// Its name for this access as LLVM writes it (`TPIDR_EL0`), empty
    /// where it has none.
    pub name: Str,
    /// `op0:op1:CRn:CRm:op2`, `op0` in bits 15:14.
    pub encoding: u16,
    /// Whether it has a name.
    pub has_name: bool,
    /// Zero.
    pub reserved: [u8; 5],
}

/// An operand written as a name from a fixed set
/// (`binbun_aarch64_named`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A64Named {
    /// The name, lower case.
    pub name: Str,
    /// What it names, a `binbun_aarch64_name_kind`.
    pub kind: u8,
    /// Zero.
    pub reserved: [u8; 7],
}

/// The SME array or a tile, whole or sliced (`binbun_aarch64_za`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64Za {
    /// The tile, where `has_tile`; else the whole array.
    pub tile: u8,
    /// Whether a tile is named.
    pub has_tile: bool,
    /// The element size, a `binbun_aarch64_element`, 0 for none.
    pub element: u8,
    /// The slice direction, a `binbun_aarch64_slice_direction`, 0 for
    /// none.
    pub direction: u8,
    /// Whether a slice is selected.
    pub has_slice: bool,
    /// Slice: the index register's number (`w12` is 12).
    pub slice_index: u8,
    /// Slice: the first offset.
    pub slice_offset: u8,
    /// Slice: the last offset of a range, where `has_last`.
    pub slice_last: u8,
    /// Slice: whether a range is written.
    pub has_last: bool,
    /// Slice: the vector group size (2, 4), 0 for none.
    pub group: u8,
    /// Zero.
    pub reserved: [u8; 6],
}

/// A braced list of ZA tiles or a slice (`binbun_aarch64_za_list`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64ZaList {
    /// A `binbun_aarch64_za_list_kind`.
    pub kind: u8,
    /// Tiles: the 64-bit tiles, bit i for `za<i>.d`.
    pub tiles: u8,
    /// Zero.
    pub reserved: [u8; 6],
    /// Slice: the slice.
    pub za: A64Za,
}

/// A register selected by a general register plus an offset
/// (`binbun_aarch64_indexed_register`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64IndexedRegister {
    /// The register selected from.
    pub register: A64Register,
    /// The index register.
    pub index: A64Register,
    /// The offset added to the index.
    pub offset: u8,
    /// Zero.
    pub reserved: [u8; 7],
}

/// The value of an operand, by its kind.
#[repr(C)]
#[derive(Clone, Copy)]
pub union A64OperandDetail {
    /// Register, writeback.
    pub register: A64Register,
    /// Register list.
    pub list: A64RegisterList,
    /// Immediate.
    pub immediate: A64Immediate,
    /// Floating-point immediate.
    pub float: A64Float,
    /// Shift.
    pub shift: A64Shift,
    /// Extend.
    pub extend: A64Extend,
    /// Memory.
    pub memory: A64Memory,
    /// Label.
    pub label: A64Label,
    /// Condition: a `binbun_aarch64_cond`.
    pub condition: u8,
    /// System register.
    pub system_register: A64SystemRegister,
    /// Named operand.
    pub named: A64Named,
    /// ZA array, tile or slice.
    pub za: A64Za,
    /// ZA list.
    pub za_list: A64ZaList,
    /// Table slice: the offset in vector lengths.
    pub table_slice: u8,
    /// Indexed register.
    pub indexed_register: A64IndexedRegister,
    /// The bytes.
    pub raw: [u64; 4],
}

impl fmt::Debug for A64OperandDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("A64OperandDetail { .. }")
    }
}

/// One operand, as the text writes it (`binbun_aarch64_operand`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct A64Operand {
    /// Which value `detail` holds, a `binbun_aarch64_operand_kind`.
    pub kind: u8,
    /// `BINBUN_ACCESS_READ` and `BINBUN_ACCESS_WRITE` bits.
    pub access: u8,
    /// Zero.
    pub reserved: [u8; 6],
    /// The value.
    pub detail: A64OperandDetail,
}

// The layouts the header describes, on 64-bit targets.
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<A64RegisterList>() == 16);
    assert!(size_of::<A64Immediate>() == 16);
    assert!(size_of::<A64Float>() == 16);
    assert!(size_of::<A64Shift>() == 8);
    assert!(size_of::<A64Extend>() == 8);
    assert!(size_of::<A64Memory>() == 32);
    assert!(size_of::<A64Label>() == 16);
    assert!(size_of::<A64SystemRegister>() == 24);
    assert!(size_of::<A64Named>() == 24);
    assert!(size_of::<A64Za>() == 16);
    assert!(size_of::<A64ZaList>() == 24);
    assert!(size_of::<A64IndexedRegister>() == 24);
    assert!(size_of::<A64OperandDetail>() == 32);
    assert!(size_of::<A64Operand>() == 40 && align_of::<A64Operand>() == 8);
};

/// Writes the instruction's operands, as the text writes them (after alias
/// selection), into `out`, up to `capacity` of them. Returns how many
/// operands the instruction has (no more than
/// `BINBUN_AARCH64_MAX_OPERANDS`), or 0 if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `out` is null or writable for `capacity` operands.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_operands(
    inst: *const A64Instruction,
    out: *mut A64Operand,
    capacity: usize,
) -> usize {
    // SAFETY: `out` is null or writable for `capacity` operands (contract).
    let out = unsafe { ffi::out_slice(out, capacity) };
    // SAFETY: the contract of `inst`.
    unsafe {
        read(inst, 0, |instruction: Instruction| {
            let operands = instruction.operands();
            let access = instruction.access();
            for ((operand, access), slot) in operands.iter().zip(access.iter()).zip(out.iter_mut())
            {
                slot.write(A64Operand::new(operand, *access));
            }
            operands.len()
        })
    }
}

impl A64Operand {
    /// `operand`, accessed as `access`, as C sees it.
    pub fn new(operand: &Operand, access: Access) -> Self {
        let mut detail = A64OperandDetail { raw: [0; 4] };
        let kind = match *operand {
            Operand::Register(register) => {
                detail.register = A64Register::new(register);
                1
            }
            Operand::List(list) => {
                detail.list = A64RegisterList::from(list);
                2
            }
            Operand::Immediate(immediate) => {
                detail.immediate = A64Immediate::from(immediate);
                3
            }
            Operand::Float(Float { value, exact }) => {
                detail.float = A64Float {
                    value,
                    exact,
                    reserved: [0; 7],
                };
                4
            }
            Operand::Shift(shift) => {
                detail.shift = A64Shift::from(shift);
                5
            }
            Operand::Extend(extend) => {
                detail.extend = A64Extend::from(extend);
                6
            }
            Operand::Memory(memory) => {
                detail.memory = A64Memory::from(memory);
                7
            }
            Operand::Writeback(register) => {
                detail.register = A64Register::new(register);
                8
            }
            Operand::Label(label) => {
                detail.label = A64Label::from(label);
                9
            }
            Operand::Condition(condition) => {
                detail.condition = condition as u8;
                10
            }
            Operand::SystemRegister(register) => {
                detail.system_register = A64SystemRegister::from(register);
                11
            }
            Operand::Named(named) => {
                detail.named = A64Named::from(named);
                12
            }
            Operand::Za(za) => {
                detail.za = A64Za::from(za);
                13
            }
            Operand::ZaList(list) => {
                detail.za_list = A64ZaList::from(list);
                14
            }
            Operand::TableSlice(offset) => {
                detail.table_slice = offset;
                15
            }
            Operand::IndexedRegister(register) => {
                detail.indexed_register = A64IndexedRegister::from(register);
                16
            }
        };
        Self {
            kind,
            access: match access {
                Access::Read => ACCESS_READ,
                Access::Write => ACCESS_WRITE,
                Access::ReadWrite => ACCESS_READ | ACCESS_WRITE,
            },
            reserved: [0; 6],
            detail,
        }
    }
}

/// `class` as a `binbun_aarch64_register_class`.
pub(crate) const fn register_class(class: RegisterClass) -> u8 {
    match class {
        RegisterClass::W => 1,
        RegisterClass::X => 2,
        RegisterClass::Wsp => 3,
        RegisterClass::Xsp => 4,
        RegisterClass::B => 5,
        RegisterClass::H => 6,
        RegisterClass::S => 7,
        RegisterClass::D => 8,
        RegisterClass::Q => 9,
        RegisterClass::V => 10,
        RegisterClass::Z => 11,
        RegisterClass::P => 12,
        RegisterClass::Pn => 13,
        RegisterClass::Zt => 14,
        RegisterClass::C => 15,
        RegisterClass::Ffr => 16,
    }
}

/// `element` as a `binbun_aarch64_element`.
pub(crate) const fn element_size(element: ElementSize) -> u8 {
    match element {
        ElementSize::B => 1,
        ElementSize::H => 2,
        ElementSize::S => 3,
        ElementSize::D => 4,
        ElementSize::Q => 5,
    }
}

/// The class a `binbun_aarch64_register_class` names, as
/// [`register_class`] numbers them.
pub(crate) const fn class_of(class: u8) -> Option<RegisterClass> {
    Some(match class {
        1 => RegisterClass::W,
        2 => RegisterClass::X,
        3 => RegisterClass::Wsp,
        4 => RegisterClass::Xsp,
        5 => RegisterClass::B,
        6 => RegisterClass::H,
        7 => RegisterClass::S,
        8 => RegisterClass::D,
        9 => RegisterClass::Q,
        10 => RegisterClass::V,
        11 => RegisterClass::Z,
        12 => RegisterClass::P,
        13 => RegisterClass::Pn,
        14 => RegisterClass::Zt,
        15 => RegisterClass::C,
        16 => RegisterClass::Ffr,
        _ => return None,
    })
}

/// The element size a `binbun_aarch64_element` names; `None` for 0 (none)
/// and for a number that is no element size.
pub(crate) const fn element_of(element: u8) -> Option<ElementSize> {
    Some(match element {
        1 => ElementSize::B,
        2 => ElementSize::H,
        3 => ElementSize::S,
        4 => ElementSize::D,
        5 => ElementSize::Q,
        _ => return None,
    })
}

/// `radix` as a `binbun_aarch64_radix`.
const fn radix(radix: Radix) -> u8 {
    match radix {
        Radix::Hex => 1,
        Radix::Decimal => 2,
        Radix::PaddedHex => 3,
    }
}

impl From<RegisterList> for A64RegisterList {
    fn from(list: RegisterList) -> Self {
        Self {
            first: A64Register::new(list.first),
            count: list.count,
            stride: list.stride,
            style: match list.style {
                ListStyle::Commas => 1,
                ListStyle::Range => 2,
            },
            reserved: [0; 5],
        }
    }
}

impl From<Immediate> for A64Immediate {
    fn from(immediate: Immediate) -> Self {
        Self {
            value: immediate.value,
            is_signed: immediate.signed,
            radix: radix(immediate.radix),
            reserved: [0; 6],
        }
    }
}

/// `kind` as a `binbun_aarch64_shift_kind`.
const fn shift_kind(kind: ShiftKind) -> u8 {
    match kind {
        ShiftKind::Lsl => 1,
        ShiftKind::Lsr => 2,
        ShiftKind::Asr => 3,
        ShiftKind::Ror => 4,
        ShiftKind::Msl => 5,
        ShiftKind::Mul => 6,
    }
}

/// `kind` as a `binbun_aarch64_extend_kind`.
const fn extend_kind(kind: ExtendKind) -> u8 {
    match kind {
        ExtendKind::Uxtb => 1,
        ExtendKind::Uxth => 2,
        ExtendKind::Uxtw => 3,
        ExtendKind::Uxtx => 4,
        ExtendKind::Sxtb => 5,
        ExtendKind::Sxth => 6,
        ExtendKind::Sxtw => 7,
        ExtendKind::Sxtx => 8,
    }
}

impl From<Shift> for A64Shift {
    fn from(shift: Shift) -> Self {
        Self {
            kind: shift_kind(shift.kind),
            amount: shift.amount,
            reserved: [0; 6],
        }
    }
}

impl From<Extend> for A64Extend {
    fn from(extend: Extend) -> Self {
        Self {
            kind: extend_kind(extend.kind),
            amount: extend.amount.unwrap_or(0),
            has_amount: extend.amount.is_some(),
            reserved: [0; 5],
        }
    }
}

impl From<Memory> for A64Memory {
    fn from(memory: Memory) -> Self {
        let mut out = Self {
            base: A64Register::new(memory.base),
            writeback: match memory.writeback {
                Writeback::None => 0,
                Writeback::Pre => 1,
                Writeback::Post => 2,
            },
            ..Self::default()
        };
        match memory.offset {
            Offset::None => {}
            Offset::Immediate(immediate) => {
                out.offset_kind = 1;
                out.offset = immediate.as_i64();
                out.offset_signed = immediate.signed;
                out.offset_radix = radix(immediate.radix);
            }
            Offset::Register { index, modifier } => {
                out.offset_kind = 2;
                out.index = A64Register::new(index);
                match modifier {
                    Modifier::None => {}
                    Modifier::Shift(shift) => {
                        out.modifier = 1;
                        out.modifier_kind = shift_kind(shift.kind);
                        out.modifier_amount = shift.amount;
                        out.modifier_has_amount = true;
                    }
                    Modifier::Extend(extend) => {
                        out.modifier = 2;
                        out.modifier_kind = extend_kind(extend.kind);
                        out.modifier_amount = extend.amount.unwrap_or(0);
                        out.modifier_has_amount = extend.amount.is_some();
                    }
                }
            }
            Offset::VectorLength(multiple) => {
                out.offset_kind = 3;
                out.offset = multiple;
            }
        }
        out
    }
}

impl From<Label> for A64Label {
    fn from(label: Label) -> Self {
        Self {
            offset: label.offset,
            base: match label.base {
                LabelBase::Instruction => 1,
                LabelBase::Page => 2,
            },
            radix: radix(label.radix),
            reserved: [0; 6],
        }
    }
}

impl From<SystemRegister> for A64SystemRegister {
    fn from(register: SystemRegister) -> Self {
        Self {
            name: register.name.map_or(Str::EMPTY, Str::new),
            encoding: register.encoding,
            has_name: register.name.is_some(),
            reserved: [0; 5],
        }
    }
}

impl From<Named> for A64Named {
    fn from(named: Named) -> Self {
        Self {
            name: Str::new(named.name),
            kind: match named.kind {
                NameKind::Prefetch => 1,
                NameKind::Barrier => 2,
                NameKind::BranchTarget => 3,
                NameKind::PstateField => 4,
                NameKind::Pattern => 5,
                NameKind::SystemOperation => 6,
                NameKind::Keyword => 7,
            },
            reserved: [0; 7],
        }
    }
}

impl From<Za> for A64Za {
    fn from(za: Za) -> Self {
        let slice = za.slice;
        Self {
            tile: za.tile.unwrap_or(0),
            has_tile: za.tile.is_some(),
            element: za.element.map_or(0, element_size),
            direction: match za.direction {
                None => 0,
                Some(SliceDirection::Horizontal) => 1,
                Some(SliceDirection::Vertical) => 2,
            },
            has_slice: slice.is_some(),
            slice_index: slice.map_or(0, |s| s.index),
            slice_offset: slice.map_or(0, |s| s.offset),
            slice_last: slice.and_then(|s| s.last).unwrap_or(0),
            has_last: slice.is_some_and(|s| s.last.is_some()),
            group: slice.and_then(|s| s.group).unwrap_or(0),
            reserved: [0; 6],
        }
    }
}

impl From<ZaList> for A64ZaList {
    fn from(list: ZaList) -> Self {
        match list {
            ZaList::Slice(slice) => Self {
                kind: 1,
                za: A64Za::from(slice),
                ..Self::default()
            },
            ZaList::Tiles(tiles) => Self {
                kind: 2,
                tiles,
                ..Self::default()
            },
        }
    }
}

impl From<IndexedRegister> for A64IndexedRegister {
    fn from(register: IndexedRegister) -> Self {
        Self {
            register: A64Register::new(register.register),
            index: A64Register::new(register.index),
            offset: register.offset,
            reserved: [0; 7],
        }
    }
}
