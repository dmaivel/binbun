//! System instruction helpers: `SysOp`, `SysLOp`, `SysOp128` over the
//! operation tables of `generated/sysreg.rs`, and the conditions LLVM adds
//! to system aliases.

use crate::generated::sysreg::{self, Register};

/// What `SysOp`, `SysLOp` and `SysOp128` return: the alias an operation of
/// `SYS`, `SYSL` or `SYSP` is written as, or the instruction itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SystemOp {
    /// Address translation (`AT`).
    At,
    /// Branch record buffer (`BRB`).
    Brb,
    /// Data cache (`DC`).
    Dc,
    /// Interrupt controller (`GIC`).
    Gic,
    /// Interrupt controller, with a result (`GICR`).
    Gicr,
    /// Interrupt controller barrier (`GSB`).
    Gsb,
    /// Instruction cache (`IC`).
    Ic,
    /// Permission lookaside buffer (`PLBI`).
    Plbi,
    /// `SYS` itself.
    Sys,
    /// `SYSL` itself.
    Sysl,
    /// `SYSP` itself.
    Sysp,
    /// TLB invalidation (`TLBI`).
    Tlbi,
    /// TLB invalidation by a register pair (`TLBIP`).
    Tlbip,
}

/// `Sys_AT`.
pub const SYS_AT: SystemOp = SystemOp::At;
/// `Sys_BRB`.
pub const SYS_BRB: SystemOp = SystemOp::Brb;
/// `Sys_DC`.
pub const SYS_DC: SystemOp = SystemOp::Dc;
/// `Sys_GIC`.
pub const SYS_GIC: SystemOp = SystemOp::Gic;
/// `Sys_GSB`.
pub const SYS_GSB: SystemOp = SystemOp::Gsb;
/// `Sys_IC`.
pub const SYS_IC: SystemOp = SystemOp::Ic;
/// `Sys_PLBI`.
pub const SYS_PLBI: SystemOp = SystemOp::Plbi;
/// `Sys_TLBI`.
pub const SYS_TLBI: SystemOp = SystemOp::Tlbi;
/// `Sys_TLBIP`.
pub const SYS_TLBIP: SystemOp = SystemOp::Tlbip;
/// `Sysl_GICR`.
pub const SYSL_GICR: SystemOp = SystemOp::Gicr;

/// `SysOp(op1, CRn, CRm, op2)`: the alias of a `SYS` operation.
pub fn sys_op(op1: u32, crn: u32, crm: u32, op2: u32) -> SystemOp {
    sysreg::sys(op1, crn, crm, op2).map_or(SystemOp::Sys, |operation| operation.category)
}

/// `SysLOp(op1, CRn, CRm, op2)`: the alias of a `SYSL` operation.
pub fn sys_l_op(op1: u32, crn: u32, crm: u32, op2: u32) -> SystemOp {
    sysreg::sysl(op1, crn, crm, op2).map_or(SystemOp::Sysl, |operation| operation.category)
}

/// `SysOp128(op1, CRn, CRm, op2)`: the alias of a `SYSP` operation.
pub fn sys_op128(op1: u32, crn: u32, crm: u32, op2: u32) -> SystemOp {
    sysreg::sysp(op1, crn, crm, op2).map_or(SystemOp::Sysp, |operation| operation.category)
}

/// Whether LLVM writes a `SYS` alias given Rt: an operation without a
/// register (`tlbi vmalle1`, `gcspushx`) only with Rt 31; otherwise LLVM
/// writes `sys` (`AArch64InstPrinter::printSysAlias`).
pub fn sys_register_allowed(op1: u32, crn: u32, crm: u32, op2: u32, rt: u32) -> bool {
    rt == 31
        || sysreg::sys(op1, crn, crm, op2)
            .is_some_and(|operation| operation.register != Register::Never)
}

/// Whether `MSR SVCR*` names a field: LLVM's `SVCRSM`, `SVCRZA` and
/// `SVCRSMZA` need `CRm<2:1> != 00`.
pub const fn svcr_field(crm: u32) -> bool {
    crm & 0b0110 != 0
}
