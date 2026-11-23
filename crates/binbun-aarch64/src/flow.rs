//! How an instruction transfers control ([`binbun_isa::Flow`]) and which
//! condition it tests, from the per-encoding rules in
//! `xtask/src/aarch64/flow.rs`.

use binbun_isa::Flow;

use crate::Instruction;
use crate::generated;
use crate::operand::{Condition as Cond, Register};

/// The condition an instruction tests: whether a conditional branch is
/// taken, a conditional trap faults, or a conditional select or compare
/// (`csel`, `ccmp`, `fcsel`) takes its first alternative.
///
/// It describes the encoding as Arm's pseudocode does, not the alias it is
/// written as: `cset w0, eq` (`csinc w0, wzr, wzr, ne`) tests `ne`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Condition {
    /// The flags satisfy a condition (`ConditionHolds(cond)`): `b.<cond>`,
    /// `bc.<cond>`, `flt.<cond>`, the conditional selects (`csel`, `csinc`,
    /// `csinv`, `csneg`, `fcsel`) and compares (`ccmp`, `ccmn`, `fccmp`,
    /// `fccmpe`). `al` and `nv` always hold.
    Flags(Cond),
    /// A general register is zero (`zero`) or not: `cbz`, `cbnz`.
    Zero {
        /// The register tested.
        register: Register,
        /// Whether the test passes when it is zero (`cbz`).
        zero: bool,
    },
    /// A bit of a general register is set (`set`) or clear: `tbz`, `tbnz`,
    /// `tfltz`, `tfltnz`.
    Bit {
        /// The register tested.
        register: Register,
        /// The bit's number.
        bit: u8,
        /// Whether the test passes when the bit is set (`tbnz`).
        set: bool,
    },
    /// `left` compared with `right` satisfies `cond` (as the flags of
    /// `cmp left, right` would): `cb<cc>`, `cbb<cc>` and `cbh<cc>` (which
    /// compare the low byte or halfword, sign- or zero-extended as `cond`
    /// is signed or not), `cflt<cc>` (`FEAT_CMPBR`, `FEAT_CFLT`).
    Compare {
        /// The condition.
        cond: Cond,
        /// The register compared.
        left: Register,
        /// What it is compared with.
        right: CompareOperand,
    },
}

/// What a [`Condition::Compare`] compares its register with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompareOperand {
    /// A general register.
    Register(Register),
    /// An immediate: unsigned for `cb<cc>`; for `cflt<cc>`, signed but for
    /// the unsigned conditions (`hi`, `lo`).
    Immediate(i64),
}

impl Instruction {
    /// How the instruction at `address` transfers control.
    ///
    /// `b`, `b.<cond>`, `bc.<cond>`, `cbz`, `tbz`, `cb<cc>` and `bl` give
    /// their target (`b.al` and `b.nv` jump unconditionally); `br`, `blr`
    /// and their pointer-authenticating forms (`braa`, `blraaz`…) give
    /// [`binbun_isa::Target::Indirect`], whatever the register (`br x30` is
    /// a jump, `blr x30` a call); `ret` (any register), `retaa`, `retab`
    /// and `retaasppc`… are [`Flow::Return`]; `eret`, `eretaa`, `eretab`,
    /// `drps` and `texit` are [`Flow::ExceptionReturn`]; `svc`, `hvc`,
    /// `smc` and `tenter` are [`Flow::SystemCall`]; `brk`, `udf`, `hlt` (the
    /// debug halt) and `flt.al` trap unconditionally, `flt.<cond>`,
    /// `cflt<cc>`, `tfltz` and `tfltnz` conditionally. The rest, `wfi`,
    /// `wfe`, `wfit`, `wfet` and `dcps1`–`dcps3` included, is
    /// [`Flow::Next`].
    #[inline]
    pub fn flow(self, address: u64) -> Flow {
        generated::flow::flow(self.encoding(), self.word(), address)
    }

    /// The condition the instruction tests, if any (see [`Condition`]).
    pub fn condition(self) -> Option<Condition> {
        generated::flow::condition(self.encoding(), self.word())
    }
}
