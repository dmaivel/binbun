//! How an instruction transfers control ([`binbun_isa::Flow`]): the kind
//! of transfer from its XED category and mnemonic, the target from its
//! operands; and which condition it tests.

use binbun_isa::{Flow, FlowStep, Target};

use super::Instruction;
use super::operand::{Memory, displacement};
use crate::generated::operand::OperandName;
use crate::generated::state::Fields;
use crate::{Mnemonic, Register};

/// The condition an instruction tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Condition {
    /// `O`: `OF` set.
    Overflow,
    /// `NO`: `OF` clear.
    NotOverflow,
    /// `B`/`C`: `CF` set (unsigned less than).
    Below,
    /// `NB`/`AE`: `CF` clear.
    NotBelow,
    /// `Z`/`E`: `ZF` set.
    Zero,
    /// `NZ`/`NE`: `ZF` clear.
    NotZero,
    /// `BE`: `CF` or `ZF` set (unsigned less or equal).
    BelowOrEqual,
    /// `NBE`/`A`: `CF` and `ZF` clear (unsigned greater).
    Above,
    /// `S`: `SF` set.
    Sign,
    /// `NS`: `SF` clear.
    NotSign,
    /// `P`: `PF` set (for x87 compares, unordered).
    Parity,
    /// `NP`: `PF` clear.
    NotParity,
    /// `L`: `SF` ≠ `OF` (signed less than).
    Less,
    /// `NL`/`GE`: `SF` = `OF`.
    NotLess,
    /// `LE`: `ZF` set or `SF` ≠ `OF` (signed less or equal).
    LessOrEqual,
    /// `NLE`/`G`: `ZF` clear and `SF` = `OF` (signed greater).
    Greater,
    /// `F`: never (APX `CCMPF`, `CTESTF`).
    False,
    /// `T`: always (APX `CCMPT`, `CTESTT`).
    True,
    /// `JCXZ`, `JECXZ`, `JRCXZ`: the count register is zero.
    CountZero,
    /// `LOOP`: the decremented count register is not zero.
    Loop,
    /// `LOOPE`: the decremented count is not zero and `ZF` is set.
    LoopZero,
    /// `LOOPNE`: the decremented count is not zero and `ZF` is clear.
    LoopNotZero,
    /// `XBEGIN`: the transaction aborts (the target is the fallback).
    TransactionAbort,
}

/// The kind of control transfer of an instruction's form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlowKind {
    /// Execution continues with the next instruction.
    Next,
    /// An unconditional jump.
    Jump,
    /// A conditional jump on a condition.
    Branch(Condition),
    /// A call.
    Call,
    /// A return from a call.
    Return,
    /// A software interrupt or deliberate exception (`INT3`, `INT n`,
    /// `UD2`).
    Trap,
    /// A software interrupt on a condition (`INTO`, `BOUND`).
    ConditionalTrap,
    /// An entry to the operating system or hypervisor (`SYSCALL`,
    /// `VMCALL`).
    SystemCall,
    /// A return from an interrupt, exception or system call (`IRET`,
    /// `SYSRET`).
    ExceptionReturn,
    /// A halt until the next interrupt (`HLT`).
    Halt,
}

/// The address `displacement` from the end of `instruction` at `address`,
/// wrapped as the instruction pointer wraps (XED's `print_rel_sym`): to 16
/// bits with a 16-bit operand size (except `XBEGIN`), else to the mode's
/// width.
#[expect(
    clippy::inline_always,
    reason = "inlined into the fast path, whose decoder state must not escape"
)]
#[inline(always)]
pub fn relative_target(instruction: &Instruction, address: u64, displacement: i64) -> u64 {
    let s = &instruction.fields;
    let mut target = address
        .wrapping_add(instruction.len() as u64)
        .wrapping_add(displacement.cast_unsigned());
    if s.eosz == 1 && instruction.mnemonic() != Mnemonic::Xbegin {
        target &= 0xffff;
    }
    if s.mode != 2 {
        target &= 0xffff_ffff;
    }
    target
}

impl Instruction {
    /// [`FlowStep::of`] this instruction at `address`, from its fields:
    /// no operand values are built (but a jump or call's memory operand).
    #[expect(
        clippy::inline_always,
        reason = "with a constant instruction number only what its flow needs remains"
    )]
    #[inline(always)]
    pub(crate) fn flow_step(&self, address: u64) -> FlowStep {
        let s = &self.fields;
        // `binbun_isa::Instruction::computed_address`: the `AGEN` operand
        // (the only one that sets `AGEN`) relative to RIP.
        let computed_address = (s.agen != 0
            && Register::from_raw(s.base0) == Some(Register::RIP)
            && Register::from_raw(s.index).is_none())
        .then(|| {
            address
                .wrapping_add(self.len() as u64)
                .wrapping_add(displacement(s).cast_unsigned())
        });
        FlowStep {
            len: self.len(),
            flow: self.flow(address),
            computed_address,
        }
    }

    /// How the instruction at `address` transfers control. Relative targets
    /// become addresses, wrapped as the instruction pointer wraps; a jump
    /// or call through `[rip+disp]` or an absolute memory address is a
    /// [`Target::Pointer`].
    #[expect(
        clippy::inline_always,
        reason = "inlined into the fast path, whose decoder state must not escape"
    )]
    #[inline(always)]
    pub fn flow(&self, address: u64) -> Flow {
        match self.info().flow {
            FlowKind::Next => Flow::Next,
            FlowKind::Jump => Flow::Jump(self.target(address)),
            FlowKind::Branch(_) => Flow::Branch(self.target(address)),
            FlowKind::Call => Flow::Call(self.target(address)),
            FlowKind::Return => Flow::Return,
            FlowKind::Trap => Flow::Trap { conditional: false },
            FlowKind::ConditionalTrap => Flow::Trap { conditional: true },
            FlowKind::SystemCall => Flow::SystemCall,
            FlowKind::ExceptionReturn => Flow::ExceptionReturn,
            FlowKind::Halt => Flow::Halt,
        }
    }

    /// The condition a conditional branch, `SETcc`, `CMOVcc` or similar
    /// tests.
    pub fn condition(&self) -> Option<Condition> {
        self.mnemonic().condition()
    }

    /// The target of a jump or call at `address`, from its first operand
    /// (only a memory operand's value is built).
    #[expect(
        clippy::inline_always,
        reason = "with a constant instruction number only one arm remains"
    )]
    #[inline(always)]
    fn target(&self, address: u64) -> Target {
        let s = &self.fields;
        let Some(template) = self.templates().next() else {
            return Target::Indirect;
        };
        match template.name {
            OperandName::Relbr => Target::Address(relative_target(self, address, s.disp)),
            OperandName::Absbr => Target::Address(s.disp.cast_unsigned()),
            OperandName::Ptr => Target::Far {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "the selector is a 16-bit immediate"
                )]
                selector: s.uimm0 as u16,
                offset: s.disp.cast_unsigned() & mask(s.brdisp_width),
            },
            OperandName::Mem0 => self.pointer(address, &self.memory(0)),
            OperandName::Agen
            | OperandName::Base0
            | OperandName::Base1
            | OperandName::Imm0
            | OperandName::Imm1
            | OperandName::Mem1
            | OperandName::Reg0
            | OperandName::Reg1
            | OperandName::Reg2
            | OperandName::Reg3
            | OperandName::Reg4
            | OperandName::Reg5
            | OperandName::Reg6
            | OperandName::Reg7
            | OperandName::Reg8
            | OperandName::Reg9 => Target::Indirect,
        }
    }

    /// The target of a near jump or call through memory operand `memory`:
    /// a pointer at a fixed address (`[rip+disp]` or `[disp]` in a segment
    /// whose base is 0), else indirect.
    fn pointer(&self, address: u64, memory: &Memory) -> Target {
        let far = matches!(self.mnemonic(), Mnemonic::JmpFar | Mnemonic::CallFar);
        let based = matches!(memory.segment, Some(Register::FS | Register::GS));
        if far || based || memory.index.is_some() {
            return Target::Indirect;
        }
        let next = address.wrapping_add(self.len() as u64);
        let at = match memory.base {
            Some(Register::RIP) => next.wrapping_add(memory.displacement.cast_unsigned()),
            Some(Register::EIP) => {
                next.wrapping_add(memory.displacement.cast_unsigned()) & 0xffff_ffff
            }
            None => memory.displacement.cast_unsigned() & mask(address_bits(&self.fields)),
            Some(_) => return Target::Indirect,
        };
        match u8::try_from(memory.size) {
            Ok(size) => Target::Pointer { address: at, size },
            Err(_) => Target::Indirect,
        }
    }
}

/// The effective address width in bits.
fn address_bits(s: &Fields) -> u8 {
    match s.easz {
        1 => 16,
        2 => 32,
        _ => 64,
    }
}

/// The low `bits` bits (all for 64).
fn mask(bits: u8) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1 << bits) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::FlowKind;
    use crate::generated::form::INSTRUCTIONS;
    use crate::generated::operand::{OperandName, SEQUENCES, template};

    /// Every form with a direct target transfers control, and every
    /// conditional branch has a relative target.
    #[test]
    fn direct_targets_belong_to_transfers() {
        for info in &INSTRUCTIONS {
            let first = usize::from(info.operands);
            let names = || {
                SEQUENCES[first..first + usize::from(info.operand_count)]
                    .iter()
                    .map(|&index| template(index).name)
            };
            let direct = names().any(|n| {
                matches!(
                    n,
                    OperandName::Relbr | OperandName::Absbr | OperandName::Ptr
                )
            });
            if direct {
                assert!(
                    matches!(
                        info.flow,
                        FlowKind::Jump | FlowKind::Branch(_) | FlowKind::Call
                    ),
                    "{:?} has a target but flow {:?}",
                    info.form,
                    info.flow
                );
            }
            if matches!(info.flow, FlowKind::Branch(_)) {
                assert!(names().any(|n| n == OperandName::Relbr), "{:?}", info.form);
            }
        }
    }
}
