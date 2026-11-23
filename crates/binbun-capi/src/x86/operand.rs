//! x86 operands (`binbun_x86_operand`).

use binbun_x86::{Action, Instruction, Operand, OperandName, Value, Visibility};

use super::{X86Instruction, read};
use crate::{ACCESS_READ, ACCESS_WRITE, ffi};

/// One operand, in XED's order (`binbun_x86_operand`). Which fields hold
/// the value depends on `kind`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct X86Operand {
    /// What the value is, a `binbun_x86_operand_kind`.
    pub kind: u8,
    /// Which decoder field holds it, a `binbun_x86_operand_field`.
    pub field: u8,
    /// Whether the text shows it, a `binbun_x86_visibility`.
    pub visibility: u8,
    /// How the instruction accesses it, a `binbun_x86_action`.
    pub action: u8,
    /// `BINBUN_ACCESS_READ` and `BINBUN_ACCESS_WRITE` bits: whether it may
    /// be read, may be written.
    pub access: u8,
    /// Memory: the index's multiplier, 1, 2, 4 or 8, or 0 without a SIB
    /// byte.
    pub scale: u8,
    /// Immediate: whether the instruction sign-extends it.
    pub signed_immediate: bool,
    /// Zero.
    pub reserved: u8,
    /// Register: the register, 0 where XED reports none.
    pub reg: u16,
    /// Memory: the segment register as XED reports it, or 0.
    pub segment: u16,
    /// Memory: the base register, or 0.
    pub base: u16,
    /// Memory: the index register, or 0.
    pub index: u16,
    /// The operand's width in bits.
    pub bits: u32,
    /// Memory: bytes accessed, 0 for an address computation.
    pub memory_size: u32,
    /// Memory: the displacement; relative: the branch displacement from the
    /// next instruction.
    pub displacement: i64,
    /// Immediate: its bytes zero-extended; second immediate: its value;
    /// field: the decoder field's value.
    pub value: u64,
}

// The layout the header describes, on 64-bit targets.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<X86Operand>() == 40 && align_of::<X86Operand>() == 8);

/// Writes the instruction's operands, in XED's order (those the text
/// shows, then implied ones), into `out`, up to `capacity` of them. Returns
/// how many operands the instruction has (no more than
/// `BINBUN_X86_MAX_OPERANDS`), or 0 if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `out` is null or writable for `capacity` operands.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_operands(
    inst: *const X86Instruction,
    out: *mut X86Operand,
    capacity: usize,
) -> usize {
    // SAFETY: `out` is null or writable for `capacity` operands (contract).
    let out = unsafe { ffi::out_slice(out, capacity) };
    // SAFETY: the contract of `inst`.
    unsafe {
        read(inst, 0, |instruction| {
            let operands = instruction.operands();
            let count = operands.len();
            for ((position, operand), slot) in operands.enumerate().zip(out.iter_mut()) {
                slot.write(X86Operand::new(instruction, position, &operand));
            }
            count
        })
    }
}

impl X86Operand {
    /// Operand `position` of `instruction`, `operand`, as C sees it.
    pub fn new(instruction: &Instruction, position: usize, operand: &Operand) -> Self {
        let mut out = Self {
            field: field(operand.name),
            visibility: match operand.visibility {
                Visibility::Explicit => 1,
                Visibility::Implicit => 2,
                Visibility::Suppressed => 3,
            },
            action: action(operand.action),
            access: if operand.action.reads() {
                ACCESS_READ
            } else {
                0
            } | if operand.action.writes() {
                ACCESS_WRITE
            } else {
                0
            },
            bits: instruction.operand_bits(position),
            ..Self::default()
        };
        match operand.value {
            Value::Register(register) => {
                out.kind = 1;
                out.reg = register.map_or(0, |r| r as u16);
            }
            Value::Memory(memory) => {
                out.kind = 2;
                out.segment = memory.segment.map_or(0, |r| r as u16);
                out.base = memory.base.map_or(0, |r| r as u16);
                out.index = memory.index.map_or(0, |r| r as u16);
                out.scale = memory.scale;
                out.displacement = memory.displacement;
                out.memory_size = memory.size;
            }
            Value::Immediate { value, signed } => {
                out.kind = 3;
                out.value = value;
                out.signed_immediate = signed;
            }
            Value::SecondImmediate(value) => {
                out.kind = 4;
                out.value = u64::from(value);
            }
            Value::Relative(displacement) => {
                out.kind = 5;
                out.displacement = displacement;
            }
            Value::Field(value) => {
                out.kind = 6;
                out.value = value;
            }
        }
        out
    }
}

/// `name` as a `binbun_x86_operand_field`.
const fn field(name: OperandName) -> u8 {
    match name {
        OperandName::Reg0 => 1,
        OperandName::Reg1 => 2,
        OperandName::Reg2 => 3,
        OperandName::Reg3 => 4,
        OperandName::Reg4 => 5,
        OperandName::Reg5 => 6,
        OperandName::Reg6 => 7,
        OperandName::Reg7 => 8,
        OperandName::Reg8 => 9,
        OperandName::Reg9 => 10,
        OperandName::Base0 => 11,
        OperandName::Base1 => 12,
        OperandName::Mem0 => 13,
        OperandName::Mem1 => 14,
        OperandName::Agen => 15,
        OperandName::Imm0 => 16,
        OperandName::Imm1 => 17,
        OperandName::Relbr => 18,
        OperandName::Absbr => 19,
        OperandName::Ptr => 20,
    }
}

/// `action` as a `binbun_x86_action`.
const fn action(action: Action) -> u8 {
    match action {
        Action::Read => 1,
        Action::Write => 2,
        Action::ReadWrite => 3,
        Action::ConditionalRead => 4,
        Action::ConditionalWrite => 5,
        Action::ConditionalReadWrite => 6,
        Action::ReadConditionalWrite => 7,
    }
}
