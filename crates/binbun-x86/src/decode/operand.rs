//! Operands of a decoded instruction, as XED reports them.
//!
//! Each instruction has a fixed list of operands (generated from XED's
//! `OPERANDS` fields, see `xtask/src/x86/operands.rs`): its name says which
//! decoder field holds the value, and it has a visibility, an access and a
//! width code. [`Instruction::operands`] pairs each with its decoded value.

use super::Instruction;
use crate::Register;
use crate::generated::operand::{
    Conversion, ElementType, OperandName, OperandWidth, SEQUENCES, template,
};
use crate::generated::state::Fields;

/// Whether an operand appears in assembly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Visibility {
    /// Written in assembly.
    Explicit,
    /// Implied by the mnemonic, but shown (`ST(0)` of x87 forms).
    Implicit,
    /// Not shown (stack pointer of `PUSH`, flags).
    Suppressed,
}

/// How an instruction accesses an operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Read.
    Read,
    /// Written.
    Write,
    /// Read and written.
    ReadWrite,
    /// Possibly read (e.g. under a `REP` prefix).
    ConditionalRead,
    /// Possibly written.
    ConditionalWrite,
    /// Possibly read, always written.
    ConditionalReadWrite,
    /// Read, possibly written.
    ReadConditionalWrite,
}

impl Action {
    /// Whether the operand may be read.
    pub const fn reads(self) -> bool {
        !matches!(self, Self::Write | Self::ConditionalWrite)
    }

    /// Whether the operand may be written.
    pub const fn writes(self) -> bool {
        !matches!(self, Self::Read | Self::ConditionalRead)
    }
}

/// One operand of an instruction's table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperandTemplate {
    /// Which decoder field holds the value.
    pub name: OperandName,
    /// Whether it appears in assembly.
    pub visibility: Visibility,
    /// How the instruction accesses it.
    pub action: Action,
    /// Its width code.
    pub width: OperandWidth,
    /// Its element type.
    pub element_type: ElementType,
    /// Decorations printed after it.
    pub conversions: &'static [Conversion],
    /// Whether it is the AVX-512 write mask (printed `{k1}` after the
    /// first operand).
    pub writemask: bool,
}

/// The kind of an operand's elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ElementBase {
    /// Count and size come from the instruction (`NELEM`, `ELEMENT_SIZE`).
    Variable,
    /// Elements of different widths.
    Struct,
    /// A signed integer of the operand's width.
    Int,
    /// An unsigned integer of the operand's width.
    Uint,
    /// 8-bit signed integer.
    Int8,
    /// 8-bit unsigned integer.
    Uint8,
    /// IEEE half precision.
    Float16,
    /// IEEE single precision.
    Single,
    /// IEEE double precision.
    Double,
    /// x87 80-bit extended precision.
    Longdouble,
    /// x87 packed BCD.
    Longbcd,
    /// bfloat16.
    Bfloat16,
    /// 8-bit brain float.
    Bfloat8,
    /// 6-bit brain float.
    Bfloat6,
    /// 4-bit brain float.
    Bfloat4,
    /// 8-bit hybrid float.
    Hfloat8,
    /// 6-bit hybrid float.
    Hfloat6,
}

/// A memory operand (or an address computation, `LEA`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Memory {
    /// The segment register as XED reports it: outside 64-bit mode the
    /// segment used, default or not; in 64-bit mode only an `FS` or `GS`
    /// override; none for an address computation.
    pub segment: Option<Register>,
    /// The base register.
    pub base: Option<Register>,
    /// The index register (for `MEM1`, always none).
    pub index: Option<Register>,
    /// The index's multiplier: 1, 2, 4 or 8, or 0 when there is no SIB
    /// byte (XED's raw value). Always 1 for `MEM1`.
    pub scale: u8,
    /// The displacement, already multiplied by the EVEX compression
    /// factor. Always 0 for `MEM1`.
    pub displacement: i64,
    /// Bytes accessed; 0 for an address computation.
    pub size: u32,
}

/// The decoded value of an operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    /// A register; `None` where XED reports `INVALID`.
    Register(Option<Register>),
    /// A memory operand or address computation.
    Memory(Memory),
    /// The first immediate.
    Immediate {
        /// Its bytes as read, zero-extended.
        value: u64,
        /// Whether the instruction sign-extends it.
        signed: bool,
    },
    /// The second immediate (`ENTER`, `EXTRQ`).
    SecondImmediate(u8),
    /// A branch displacement, relative to the next instruction.
    Relative(i64),
    /// The value of another decoder field (`PTR`, `ABSBR`).
    Field(u64),
}

/// An operand of a decoded instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Operand {
    /// Which decoder field holds the value.
    pub name: OperandName,
    /// Whether it appears in assembly.
    pub visibility: Visibility,
    /// How the instruction accesses it.
    pub action: Action,
    /// Its width code; [`OperandWidth::bits`] gives the size per
    /// effective operand size.
    pub width: OperandWidth,
    /// The decoded value.
    pub value: Value,
    /// Whether it is the AVX-512 write mask: `k0` there means no masking
    /// (no read of `k0`).
    pub writemask: bool,
}

impl Instruction {
    /// The instruction's operands, in XED's order: those written in
    /// assembly, then implied ones (stack, flags).
    pub fn operands(&self) -> impl ExactSizeIterator<Item = Operand> + '_ {
        self.templates().map(move |template| Operand {
            name: template.name,
            visibility: template.visibility,
            action: template.action,
            width: template.width,
            value: self.value(template.name),
            writemask: template.writemask,
        })
    }

    pub(super) fn templates(
        &self,
    ) -> impl ExactSizeIterator<Item = &'static OperandTemplate> + 'static {
        let info = self.info();
        let (first, count) = (usize::from(info.operands), usize::from(info.operand_count));
        SEQUENCES
            .get(first..first + count)
            .unwrap_or_default()
            .iter()
            .map(|&index| template(index))
    }

    fn value(&self, name: OperandName) -> Value {
        let s = &self.fields;
        let register = |raw| Value::Register(Register::from_raw(raw));
        match name {
            OperandName::Reg0 => register(s.reg0),
            OperandName::Reg1 => register(s.reg1),
            OperandName::Reg2 => register(s.reg2),
            OperandName::Reg3 => register(s.reg3),
            OperandName::Reg4 => register(s.reg4),
            OperandName::Reg5 => register(s.reg5),
            OperandName::Reg6 => register(s.reg6),
            OperandName::Reg7 => register(s.reg7),
            OperandName::Reg8 => register(s.reg8),
            OperandName::Reg9 => register(s.reg9),
            OperandName::Base0 => register(s.base0),
            OperandName::Base1 => register(s.base1),
            OperandName::Mem0 | OperandName::Agen => Value::Memory(self.memory(0)),
            OperandName::Mem1 => Value::Memory(self.memory(1)),
            OperandName::Imm0 => Value::Immediate {
                value: s.uimm0,
                signed: s.imm0signed != 0,
            },
            OperandName::Imm1 => Value::SecondImmediate(s.uimm1),
            OperandName::Relbr => Value::Relative(if matches!(s.brdisp_width, 8 | 16 | 32 | 64) {
                s.disp
            } else {
                0
            }),
            OperandName::Absbr => Value::Field(u64::from(s.absbr)),
            OperandName::Ptr => Value::Field(u64::from(s.ptr)),
        }
    }

    /// Memory operand `index` (0 or 1), as XED's
    /// `xed_decoded_inst_get_{seg,base,index}_reg`, `get_scale`,
    /// `get_memory_displacement` and `get_memory_operand_length`.
    pub(super) fn memory(&self, index: usize) -> Memory {
        let s = &self.fields;
        let first = index == 0;
        Memory {
            segment: Register::from_raw(if first { s.seg0 } else { s.seg1 }),
            base: Register::from_raw(if first { s.base0 } else { s.base1 }),
            index: if first {
                Register::from_raw(s.index)
            } else {
                None
            },
            scale: if first { s.scale } else { 1 },
            displacement: if first { displacement(s) } else { 0 },
            size: self.memory_size(index),
        }
    }

    fn memory_size(&self, index: usize) -> u32 {
        let s = &self.fields;
        let memory_operands = usize::from(s.mem0) + usize::from(s.mem1) + usize::from(s.agen);
        if memory_operands <= index {
            return 0;
        }
        let Some(template) = self.templates().find(|t| match index {
            0 => matches!(t.name, OperandName::Mem0 | OperandName::Agen),
            _ => t.name == OperandName::Mem1,
        }) else {
            return 0;
        };
        let bits = self.code_bits(template.width);
        let bits = if bits == 0 {
            u32::from(s.nelem) * u32::from(s.element_size)
        } else {
            bits
        };
        bits >> 3
    }

    /// The effective operand width in bits: 8, 16, 32 or 64 (XED's
    /// `xed_operand_values_get_effective_operand_width`).
    pub fn operand_width(&self) -> u32 {
        8 << self.fields.eosz.min(3)
    }

    /// The effective address width in bits: 16, 32 or 64 (XED's `EASZ`),
    /// or 0 when the instruction has none.
    pub fn address_width(&self) -> u32 {
        match self.fields.easz {
            1 => 16,
            2 => 32,
            3 => 64,
            _ => 0,
        }
    }

    /// The stack address width in bits: 16, 32 or 64 (XED's `SMODE`).
    pub fn stack_address_width(&self) -> u32 {
        16 << self.fields.smode.min(2)
    }

    /// Whether an AVX-512 write mask zeroes the elements it masks (`{z}`,
    /// EVEX.z) rather than keeping them (XED's `ZEROING`).
    pub fn zeroing(&self) -> bool {
        self.fields.zeroing != 0
    }

    /// The width in bits of operand `position` (in [`operands`](Self::operands)
    /// order), as XED's `xed_decoded_inst_operand_length_bits`: a register
    /// operand's width code at the effective operand size, an address
    /// computation's address width, otherwise the width code's bits or, for
    /// vector operands, the element count times the element size. 0 for a
    /// position past the last operand.
    pub fn operand_bits(&self, position: usize) -> u32 {
        let s = &self.fields;
        let Some(t) = self.templates().nth(position) else {
            return 0;
        };
        if t.name.is_register() {
            return if t.width == OperandWidth::Invalid {
                0
            } else {
                self.code_bits(t.width)
            };
        }
        if t.name == OperandName::Agen {
            return self.address_width();
        }
        let bits = self.code_bits(t.width);
        if bits == 0 {
            u32::from(s.nelem) * u32::from(s.element_size)
        } else {
            bits
        }
    }

    /// Bits of a width code for this instruction's sizes (XED's
    /// `xed_decoded_inst_get_operand_width_bits`); 0 where the width comes
    /// from the element count.
    fn code_bits(&self, width: OperandWidth) -> u32 {
        if width == OperandWidth::Ssz {
            self.stack_address_width()
        } else if width == OperandWidth::Asz {
            self.address_width()
        } else {
            let bits = width.bits();
            u32::from(
                bits.get(usize::from(self.fields.eosz))
                    .copied()
                    .unwrap_or(0),
            )
        }
    }
}

impl OperandName {
    /// Whether the operand is a register field (`REG0`–`REG9`, `BASE0`,
    /// `BASE1`).
    pub const fn is_register(self) -> bool {
        matches!(
            self,
            Self::Reg0
                | Self::Reg1
                | Self::Reg2
                | Self::Reg3
                | Self::Reg4
                | Self::Reg5
                | Self::Reg6
                | Self::Reg7
                | Self::Reg8
                | Self::Reg9
                | Self::Base0
                | Self::Base1
        )
    }
}

/// The memory displacement, scaled for EVEX compressed 8-bit displacements
/// (XED's `xed_operand_values_get_memory_displacement_int64`).
pub(super) fn displacement(s: &Fields) -> i64 {
    if s.brdisp_width != 0 {
        return 0;
    }
    match s.disp_width {
        8 if s.nelem != 0 => s.disp * ((i64::from(s.nelem) * i64::from(s.element_size)) >> 3),
        8 | 16 | 32 | 64 => s.disp,
        _ => 0,
    }
}
