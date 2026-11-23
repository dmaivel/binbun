//! [`binbun_isa`]'s traits for x86, so that architecture-neutral analyses
//! can use this decoder.

use binbun_isa::{Architecture, Flow, FlowStep};

use crate::{
    DecodeError, Instruction, MAX_LENGTH, Mode, OperandName, Register, Value, decode, decode_flow,
};

/// The x86 instruction set (16, 32 and 64-bit), for analyses written
/// against [`binbun_isa::Architecture`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct X86;

impl Architecture for X86 {
    type Instruction = Instruction;
    type Error = DecodeError;
    type Mode = Mode;

    const MAX_LENGTH: usize = MAX_LENGTH;

    fn decode(&self, bytes: &[u8], mode: Mode) -> Result<Instruction, DecodeError> {
        decode(bytes, mode)
    }

    fn decode_flow(&self, bytes: &[u8], mode: Mode, address: u64) -> Result<FlowStep, DecodeError> {
        decode_flow(bytes, mode, address)
    }
}

impl binbun_isa::Instruction for Instruction {
    fn len(&self) -> usize {
        Instruction::len(self)
    }

    fn flow(&self, address: u64) -> Flow {
        Instruction::flow(self, address)
    }

    /// A RIP-relative address computation (`lea reg, [rip+disp]`).
    fn computed_address(&self, address: u64) -> Option<u64> {
        self.operands().find_map(|operand| match operand.value {
            Value::Memory(memory)
                if operand.name == OperandName::Agen
                    && memory.base == Some(Register::RIP)
                    && memory.index.is_none() =>
            {
                let next = address.wrapping_add(Instruction::len(self) as u64);
                Some(next.wrapping_add(memory.displacement.cast_unsigned()))
            }
            Value::Memory(_)
            | Value::Register(_)
            | Value::Immediate { .. }
            | Value::SecondImmediate(_)
            | Value::Relative(_)
            | Value::Field(_) => None,
        })
    }
}
