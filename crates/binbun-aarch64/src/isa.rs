//! [`binbun_isa`]'s traits for A64, so that architecture-neutral analyses
//! can use this decoder.

use binbun_isa::{Architecture, Flow};

use crate::{Encoding, Error, Instruction, Operand, decode_bytes};

/// The processor mode instructions are decoded for: AArch64 has one
/// instruction set (A32 and T32 are AArch32's, which this crate does not
/// decode).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Mode {
    /// A64.
    #[default]
    A64,
}

/// The A64 instruction set, for analyses written against
/// [`binbun_isa::Architecture`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct AArch64;

impl Architecture for AArch64 {
    type Instruction = Instruction;
    type Error = Error;
    type Mode = Mode;

    const MAX_LENGTH: usize = 4;

    fn decode(&self, bytes: &[u8], mode: Mode) -> Result<Instruction, Error> {
        let Mode::A64 = mode;
        decode_bytes(bytes)
    }
}

impl binbun_isa::Instruction for Instruction {
    fn len(&self) -> usize {
        4
    }

    fn flow(&self, address: u64) -> Flow {
        Instruction::flow(*self, address)
    }

    /// The address `adr` computes. `adrp` computes a 4 KiB page, not a
    /// pointer: the address it is a part of is known only once the
    /// instruction adding the low bits is paired with it (after lifting).
    fn computed_address(&self, address: u64) -> Option<u64> {
        if self.encoding() != Encoding::ADR_only_pcreladdr {
            return None;
        }
        self.operands().iter().find_map(|operand| match *operand {
            Operand::Label(label) => Some(label.target(address)),
            Operand::Register(_)
            | Operand::List(_)
            | Operand::Immediate(_)
            | Operand::Float(_)
            | Operand::Shift(_)
            | Operand::Extend(_)
            | Operand::Memory(_)
            | Operand::Writeback(_)
            | Operand::Condition(_)
            | Operand::SystemRegister(_)
            | Operand::Named(_)
            | Operand::Za(_)
            | Operand::ZaList(_)
            | Operand::TableSlice(_)
            | Operand::IndexedRegister(_) => None,
        })
    }
}
