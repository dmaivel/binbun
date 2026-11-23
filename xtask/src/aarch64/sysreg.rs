//! The decoder's `sysreg.rs`: the names `MRS`, `MSR`, `MRRS` and `MSRR`
//! write system registers by, the `PSTATE` fields of `MSR (immediate)`, and
//! the operations of `SYS`, `SYSL` and `SYSP` (`DC`, `IC`, `AT`, `TLBI`,
//! `TLBIP`, `GICR`, …): their name, the `SysOp` category the alias
//! conditions compare with and whether they take a register.
//!
//! The names are the A64 accessors of `Registers.json` (array registers
//! such as `DBGBVR<n>_EL1` expanded), with LLVM 22's differences applied, as
//! binbun writes LLVM's text: the tables below were derived by running every
//! `op0:op1:CRn:CRm:op2` encoding through LLVM's disassembler (`MRS` and
//! `MSR` with op0 2 and 3; `SYS`, `SYSL`, `SYSP` with Rt 31 and not 31) and
//! comparing with the names generated from Arm's tables, not by guessing.
//! LLVM writes the `MRS` (read) and `MSR` (write) names for `MRRS` and
//! `MSRR`. Every feature is assumed (LLVM's `+all`), so accessor conditions
//! are not consulted.

use std::collections::BTreeMap;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use xtask::aarchmrs::{AccessorValue, Expr, Package, SystemAccessor};

use super::{AARCHMRS_NOTICE, output};
use crate::Result;
use crate::codegen::{GeneratedFile, count, lit};

/// Read by `MRS` and `MRRS`.
const READ: u8 = 1;
/// Written by `MSR` and `MSRR`.
const WRITE: u8 = 2;
/// Read and written.
const BOTH: u8 = READ | WRITE;

/// Register names LLVM 22 has where Arm's 2026-09 tables have none
/// (registers Arm withdrew: legacy trace, Armv8-R, older drafts), with the
/// encoding as LLVM writes it generically and the accesses LLVM names.
const LLVM_REGISTERS: &[(&str, &str, u8)] = &[
    ("TRCPROCSELR", "S2_1_C0_C2_0", BOTH),
    ("TRCVDCTLR", "S2_1_C0_C8_2", BOTH),
    ("TRCVDSACCTLR", "S2_1_C0_C9_2", BOTH),
    ("TRCVDARCCTLR", "S2_1_C0_C10_2", BOTH),
    ("TRCOSLAR", "S2_1_C1_C0_4", WRITE),
    ("TRCPDCR", "S2_1_C1_C4_4", BOTH),
    ("TRCPDSR", "S2_1_C1_C5_4", READ),
    ("TRCDVCVR0", "S2_1_C2_C0_4", BOTH),
    ("TRCDVCVR4", "S2_1_C2_C0_5", BOTH),
    ("TRCDVCMR0", "S2_1_C2_C0_6", BOTH),
    ("TRCDVCMR4", "S2_1_C2_C0_7", BOTH),
    ("TRCDVCVR1", "S2_1_C2_C4_4", BOTH),
    ("TRCDVCVR5", "S2_1_C2_C4_5", BOTH),
    ("TRCDVCMR1", "S2_1_C2_C4_6", BOTH),
    ("TRCDVCMR5", "S2_1_C2_C4_7", BOTH),
    ("TRCDVCVR2", "S2_1_C2_C8_4", BOTH),
    ("TRCDVCVR6", "S2_1_C2_C8_5", BOTH),
    ("TRCDVCMR2", "S2_1_C2_C8_6", BOTH),
    ("TRCDVCMR6", "S2_1_C2_C8_7", BOTH),
    ("TRCDVCVR3", "S2_1_C2_C12_4", BOTH),
    ("TRCDVCVR7", "S2_1_C2_C12_5", BOTH),
    ("TRCDVCMR3", "S2_1_C2_C12_6", BOTH),
    ("TRCDVCMR7", "S2_1_C2_C12_7", BOTH),
    ("TRCITCTRL", "S2_1_C7_C0_4", BOTH),
    ("TRCDEVTYPE", "S2_1_C7_C3_7", READ),
    ("TRCPIDR4", "S2_1_C7_C4_7", READ),
    ("TRCPIDR5", "S2_1_C7_C5_7", READ),
    ("TRCPIDR6", "S2_1_C7_C6_7", READ),
    ("TRCPIDR7", "S2_1_C7_C7_7", READ),
    ("TRCPIDR0", "S2_1_C7_C8_7", READ),
    ("TRCPIDR1", "S2_1_C7_C9_7", READ),
    ("TRCDEVAFF0", "S2_1_C7_C10_6", READ),
    ("TRCPIDR2", "S2_1_C7_C10_7", READ),
    ("TRCDEVAFF1", "S2_1_C7_C11_6", READ),
    ("TRCPIDR3", "S2_1_C7_C11_7", READ),
    ("TRCLAR", "S2_1_C7_C12_6", WRITE),
    ("TRCCIDR0", "S2_1_C7_C12_7", READ),
    ("TRCLSR", "S2_1_C7_C13_6", READ),
    ("TRCCIDR1", "S2_1_C7_C13_7", READ),
    ("TRCCIDR2", "S2_1_C7_C14_7", READ),
    ("TRCCIDR3", "S2_1_C7_C15_7", READ),
    ("TEECR32_EL1", "S2_2_C0_C0_0", BOTH),
    ("TEEHBR32_EL1", "S2_2_C1_C0_0", BOTH),
    ("MPUIR_EL1", "S3_0_C0_C0_4", BOTH),
    ("TPMIN1_EL1", "S3_0_C2_C2_6", BOTH),
    ("TPMAX1_EL1", "S3_0_C2_C2_7", BOTH),
    ("PRENR_EL1", "S3_0_C6_C1_1", BOTH),
    ("PRSELR_EL1", "S3_0_C6_C2_1", BOTH),
    ("PRBAR_EL1", "S3_0_C6_C8_0", BOTH),
    ("PRLAR_EL1", "S3_0_C6_C8_1", BOTH),
    ("PRBAR1_EL1", "S3_0_C6_C8_4", BOTH),
    ("PRLAR1_EL1", "S3_0_C6_C8_5", BOTH),
    ("PRBAR2_EL1", "S3_0_C6_C9_0", BOTH),
    ("PRLAR2_EL1", "S3_0_C6_C9_1", BOTH),
    ("PRBAR3_EL1", "S3_0_C6_C9_4", BOTH),
    ("PRLAR3_EL1", "S3_0_C6_C9_5", BOTH),
    ("PRBAR4_EL1", "S3_0_C6_C10_0", BOTH),
    ("PRLAR4_EL1", "S3_0_C6_C10_1", BOTH),
    ("PRBAR5_EL1", "S3_0_C6_C10_4", BOTH),
    ("PRLAR5_EL1", "S3_0_C6_C10_5", BOTH),
    ("PRBAR6_EL1", "S3_0_C6_C11_0", BOTH),
    ("PRLAR6_EL1", "S3_0_C6_C11_1", BOTH),
    ("PRBAR7_EL1", "S3_0_C6_C11_4", BOTH),
    ("PRLAR7_EL1", "S3_0_C6_C11_5", BOTH),
    ("PRBAR8_EL1", "S3_0_C6_C12_0", BOTH),
    ("PRLAR8_EL1", "S3_0_C6_C12_1", BOTH),
    ("PRBAR9_EL1", "S3_0_C6_C12_4", BOTH),
    ("PRLAR9_EL1", "S3_0_C6_C12_5", BOTH),
    ("PRBAR10_EL1", "S3_0_C6_C13_0", BOTH),
    ("PRLAR10_EL1", "S3_0_C6_C13_1", BOTH),
    ("PRBAR11_EL1", "S3_0_C6_C13_4", BOTH),
    ("PRLAR11_EL1", "S3_0_C6_C13_5", BOTH),
    ("PRBAR12_EL1", "S3_0_C6_C14_0", BOTH),
    ("PRLAR12_EL1", "S3_0_C6_C14_1", BOTH),
    ("PRBAR13_EL1", "S3_0_C6_C14_4", BOTH),
    ("PRLAR13_EL1", "S3_0_C6_C14_5", BOTH),
    ("PRBAR14_EL1", "S3_0_C6_C15_0", BOTH),
    ("PRLAR14_EL1", "S3_0_C6_C15_1", BOTH),
    ("PRBAR15_EL1", "S3_0_C6_C15_4", BOTH),
    ("PRLAR15_EL1", "S3_0_C6_C15_5", BOTH),
    ("PMIAR_EL1", "S3_0_C9_C14_7", BOTH),
    ("ICC_PPI_HMR0_EL1", "S3_0_C12_C10_0", WRITE),
    ("ICC_PPI_HMR1_EL1", "S3_0_C12_C10_1", WRITE),
    ("ICV_HPPIR_EL1", "S3_0_C12_C10_3", WRITE),
    ("ICC_HAPR_EL1", "S3_1_C12_C0_3", READ),
    ("ICV_HAPR_EL1", "S3_1_C12_C0_3", WRITE),
    ("TPMIN1_EL0", "S3_3_C2_C2_6", BOTH),
    ("TPMAX1_EL0", "S3_3_C2_C2_7", BOTH),
    ("MPUIR_EL2", "S3_4_C0_C0_4", BOTH),
    ("TPMIN1_EL2", "S3_4_C2_C2_6", BOTH),
    ("TPMAX1_EL2", "S3_4_C2_C2_7", BOTH),
    ("PRENR_EL2", "S3_4_C6_C1_1", BOTH),
    ("PRSELR_EL2", "S3_4_C6_C2_1", BOTH),
    ("PRBAR_EL2", "S3_4_C6_C8_0", BOTH),
    ("PRLAR_EL2", "S3_4_C6_C8_1", BOTH),
    ("PRBAR1_EL2", "S3_4_C6_C8_4", BOTH),
    ("PRLAR1_EL2", "S3_4_C6_C8_5", BOTH),
    ("PRBAR2_EL2", "S3_4_C6_C9_0", BOTH),
    ("PRLAR2_EL2", "S3_4_C6_C9_1", BOTH),
    ("PRBAR3_EL2", "S3_4_C6_C9_4", BOTH),
    ("PRLAR3_EL2", "S3_4_C6_C9_5", BOTH),
    ("PRBAR4_EL2", "S3_4_C6_C10_0", BOTH),
    ("PRLAR4_EL2", "S3_4_C6_C10_1", BOTH),
    ("PRBAR5_EL2", "S3_4_C6_C10_4", BOTH),
    ("PRLAR5_EL2", "S3_4_C6_C10_5", BOTH),
    ("PRBAR6_EL2", "S3_4_C6_C11_0", BOTH),
    ("PRLAR6_EL2", "S3_4_C6_C11_1", BOTH),
    ("PRBAR7_EL2", "S3_4_C6_C11_4", BOTH),
    ("PRLAR7_EL2", "S3_4_C6_C11_5", BOTH),
    ("PRBAR8_EL2", "S3_4_C6_C12_0", BOTH),
    ("PRLAR8_EL2", "S3_4_C6_C12_1", BOTH),
    ("PRBAR9_EL2", "S3_4_C6_C12_4", BOTH),
    ("PRLAR9_EL2", "S3_4_C6_C12_5", BOTH),
    ("PRBAR10_EL2", "S3_4_C6_C13_0", BOTH),
    ("PRLAR10_EL2", "S3_4_C6_C13_1", BOTH),
    ("PRBAR11_EL2", "S3_4_C6_C13_4", BOTH),
    ("PRLAR11_EL2", "S3_4_C6_C13_5", BOTH),
    ("PRBAR12_EL2", "S3_4_C6_C14_0", BOTH),
    ("PRLAR12_EL2", "S3_4_C6_C14_1", BOTH),
    ("PRBAR13_EL2", "S3_4_C6_C14_4", BOTH),
    ("PRLAR13_EL2", "S3_4_C6_C14_5", BOTH),
    ("PRBAR14_EL2", "S3_4_C6_C15_0", BOTH),
    ("PRLAR14_EL2", "S3_4_C6_C15_1", BOTH),
    ("PRBAR15_EL2", "S3_4_C6_C15_4", BOTH),
    ("PRLAR15_EL2", "S3_4_C6_C15_5", BOTH),
    ("MPAMVIDCR_EL2", "S3_4_C10_C7_0", BOTH),
    ("MPAMVIDSR_EL2", "S3_4_C10_C7_1", BOTH),
    ("CNTSCALE_EL2", "S3_4_C14_C0_4", BOTH),
    ("CNTISCALE_EL2", "S3_4_C14_C0_5", BOTH),
    ("CNTVFRQ_EL2", "S3_4_C14_C0_7", BOTH),
    ("TPMIN1_EL12", "S3_5_C2_C2_6", BOTH),
    ("TPMAX1_EL12", "S3_5_C2_C2_7", BOTH),
    ("MPAMVIDSR_EL3", "S3_6_C10_C7_1", BOTH),
];

/// Arm's register names LLVM 22 lacks (newer than LLVM): it writes their
/// encodings generically.
const LLVM_LACKS: &[&str] = &[
    "CCONTIDR_EL1",
    "ICH_PPI_HVIR0_EL2",
    "ICH_PPI_HVIR1_EL2",
    "SCR2_EL3",
];

/// Arm's register names LLVM 22 writes differently: `(Arm, LLVM)`.
const LLVM_RENAMES: &[(&str, &str)] = &[
    ("TRCEXTINSELR0", "TRCEXTINSELR"),
    ("TPCR0_EL0", "TPMIN0_EL0"),
    ("TPCR1_EL0", "TPMAX0_EL0"),
    ("TPCR0_EL1", "TPMIN0_EL1"),
    ("TPCR1_EL1", "TPMAX0_EL1"),
    ("TPCR0_EL12", "TPMIN0_EL12"),
    ("TPCR1_EL12", "TPMAX0_EL12"),
    ("TPCR0_EL2", "TPMIN0_EL2"),
    ("TPCR1_EL2", "TPMAX0_EL2"),
];

/// Whether a system operation takes a general register (`Xt`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Register {
    /// Never (`TLBI VMALLE1`): LLVM writes `SYS` when Rt is not 31.
    Never,
    /// Optionally (`TLBI VMALLE1OS`, `FEAT_TLBID`): written unless Rt is 31.
    Optional,
    /// Always (`TLBI VAE1`): written even as `xzr`.
    Always,
}

impl Register {
    /// Arm's answer: the operation has a register when its register has a
    /// field layout (always, or under a feature condition).
    fn of(accessor: &SystemAccessor) -> Self {
        if accessor.fieldsets.is_empty() {
            Self::Never
        } else if accessor.fieldsets.contains(&Expr::Bool(true)) {
            Self::Always
        } else {
            Self::Optional
        }
    }

    fn variant(self) -> TokenStream {
        match self {
            Self::Never => quote! { Register::Never },
            Self::Optional => quote! { Register::Optional },
            Self::Always => quote! { Register::Always },
        }
    }
}

/// Operations LLVM 22 has where Arm's tables have none: LLVM derives an
/// nXS variant of every `TLBI` operation, also of those Arm defines none
/// for. `(instruction, op1, CRn, CRm, op2, name, register)`.
const LLVM_OPERATIONS: &[(&str, u16, u16, u16, u16, &str, Register)] = &[
    ("TLBI", 6, 9, 1, 4, "PAALLOSNXS", Register::Never),
    ("TLBI", 6, 9, 4, 3, "RPAOSNXS", Register::Always),
    ("TLBI", 6, 9, 4, 7, "RPALOSNXS", Register::Always),
    ("TLBI", 6, 9, 7, 4, "PAALLNXS", Register::Never),
];

/// Operations whose register LLVM 22 treats otherwise than Arm's field
/// layouts say (its `NeedsReg`, `OptionalReg`): `(instruction, name,
/// register)`.
const LLVM_REGISTER: &[(&str, &str, Register)] = &[
    ("GIC", "CDEOI", Register::Never),
    ("PLBI", "ALLE1IS", Register::Optional),
    ("PLBI", "ALLE1ISNXS", Register::Optional),
    ("PLBI", "ALLE1OS", Register::Optional),
    ("PLBI", "ALLE1OSNXS", Register::Optional),
    ("PLBI", "ALLE2IS", Register::Optional),
    ("PLBI", "ALLE2ISNXS", Register::Optional),
    ("PLBI", "ALLE2OS", Register::Optional),
    ("PLBI", "ALLE2OSNXS", Register::Optional),
    ("PLBI", "VMALLE1IS", Register::Optional),
    ("PLBI", "VMALLE1ISNXS", Register::Optional),
    ("PLBI", "VMALLE1OS", Register::Optional),
    ("PLBI", "VMALLE1OSNXS", Register::Optional),
    ("TLBI", "ALLE3IS", Register::Optional),
    ("TLBI", "ALLE3ISNXS", Register::Optional),
    ("TLBI", "ALLE3OS", Register::Optional),
    ("TLBI", "ALLE3OSNXS", Register::Optional),
    ("TLBI", "VMALLWS2E1", Register::Never),
    ("TLBI", "VMALLWS2E1NXS", Register::Never),
];

/// The encodings of `SYS`, `SYSL` and `SYSP`, by the table their
/// operations go in.
const INSTRUCTIONS: &[(&str, &str)] = &[
    ("SYS_CR_systeminstrs", "SYS"),
    ("SYSL_RC_systeminstrs", "SYSL"),
    ("SYSP_CR_syspairinstrs", "SYSP"),
];

/// The `SystemOp` variant (the decoder's `pseudocode::SystemOp`) of the
/// operations of an accessor instruction that `SysOp`, `SysLOp` or
/// `SysOp128` names (`A64.DC` → `Sys_DC`); others are the instruction's
/// own (`Sys_SYS`, …).
const CATEGORIES: &[(&str, &str)] = &[
    ("AT", "At"),
    ("BRB", "Brb"),
    ("DC", "Dc"),
    ("GIC", "Gic"),
    ("GICR", "Gicr"),
    ("GSB", "Gsb"),
    ("IC", "Ic"),
    ("PLBI", "Plbi"),
    ("TLBI", "Tlbi"),
    ("TLBIP", "Tlbip"),
];

/// One field value of an accessor encoding: index variable values to the
/// field's values (a pattern with `x` bits has several).
fn values(value: &AccessorValue, index: Option<(&str, u64)>) -> Result<Option<Vec<u64>>> {
    let variable = |name: &str| {
        index
            .filter(|(variable, _)| *variable == name)
            .map(|(_, n)| n)
    };
    Ok(Some(match value {
        AccessorValue::Bits(pattern) => (0..1u64 << pattern.width())
            .filter(|value| pattern.matches(*value))
            .collect(),
        AccessorValue::Variable { name, slices } => {
            let Some(n) = variable(name) else {
                // `S3_<op1>_C<Cn>_C<Cm>_<op2>`: the generic form.
                return Ok(None);
            };
            let mut out = 0;
            for slice in slices {
                out = (out << slice.width) | ((n >> slice.start) & ((1 << slice.width) - 1));
            }
            vec![out]
        }
        AccessorValue::Concatenation(text) => vec![concatenation(text, &variable)?],
    }))
}

/// The value of `'011':p[3]`, `m[2:0]:'0'` and the like.
fn concatenation(text: &str, variable: &dyn Fn(&str) -> Option<u64>) -> Result<u64> {
    let bad = || format!("concatenation `{text}`");
    let mut out = 0u64;
    let mut rest = text;
    while !rest.is_empty() {
        rest = rest.strip_prefix(':').unwrap_or(rest);
        if let Some(bits) = rest.strip_prefix('\'') {
            let (bits, after) = bits.split_once('\'').ok_or_else(bad)?;
            let width = u32::try_from(bits.len())?;
            out = (out << width) | u64::from_str_radix(bits, 2)?;
            rest = after;
            continue;
        }
        let (name, after) = rest.split_once('[').ok_or_else(bad)?;
        let (range, after) = after.split_once(']').ok_or_else(bad)?;
        let (high, low) = range.split_once(':').unwrap_or((range, range));
        let (high, low): (u32, u32) = (high.parse()?, low.parse()?);
        let n = variable(name).ok_or_else(bad)?;
        let width = high + 1 - low;
        out = (out << width) | ((n >> low) & ((1 << width) - 1));
        rest = after;
    }
    Ok(out)
}

/// Every `(fields, name)` an accessor gives: fields by name, the name with
/// the index substituted.
fn expand(accessor: &SystemAccessor) -> Result<Vec<(BTreeMap<&str, u64>, String)>> {
    let indices: Vec<Option<(&str, u64)>> = match &accessor.index {
        None => vec![None],
        Some(index) => index
            .ranges
            .iter()
            .flat_map(|range| {
                (range.start..range.start + range.width)
                    .map(|n| Some((index.variable.as_str(), u64::from(n))))
            })
            .collect(),
    };
    let mut out = Vec::new();
    for index in indices {
        for encoding in &accessor.encodings {
            let mut name = encoding.asm_value.clone().unwrap_or_default();
            if let Some((variable, n)) = index {
                name = name.replace(&format!("<{variable}>"), &n.to_string());
            }
            let mut combinations = vec![BTreeMap::new()];
            for (field, value) in &encoding.fields {
                let Some(values) = values(value, index)? else {
                    combinations.clear();
                    break;
                };
                combinations = combinations
                    .into_iter()
                    .flat_map(|fields| {
                        values.iter().map(move |value| {
                            let mut fields = fields.clone();
                            fields.insert(field.as_str(), *value);
                            fields
                        })
                    })
                    .collect();
            }
            out.extend(
                combinations
                    .into_iter()
                    .map(|fields| (fields, name.clone())),
            );
        }
    }
    Ok(out)
}

/// `op0:op1:CRn:CRm:op2` (without op0 when `op0` is false).
fn key(fields: &BTreeMap<&str, u64>, op0: bool) -> Result<u16> {
    let get = |name: &str| {
        fields
            .get(name)
            .copied()
            .ok_or_else(|| format!("accessor without {name}"))
    };
    let low = (get("op1")? << 11) | (get("CRn")? << 7) | (get("CRm")? << 3) | get("op2")?;
    let value = if op0 { (get("op0")? << 14) | low } else { low };
    Ok(u16::try_from(value)?)
}

/// `S3_0_C6_C8_4` → its encoding.
fn generic(text: &str) -> Result<u16> {
    let bad = || format!("generic register `{text}`");
    let parts: Vec<&str> = text.split('_').collect();
    let [op0, op1, crn, crm, op2] = parts.as_slice() else {
        return Err(bad().into());
    };
    let number = |part: &str, prefix: char| -> Result<u16> {
        Ok(part.strip_prefix(prefix).ok_or_else(bad)?.parse()?)
    };
    Ok((number(op0, 'S')? << 14)
        | (op1.parse::<u16>()? << 11)
        | (number(crn, 'C')? << 7)
        | (number(crm, 'C')? << 3)
        | op2.parse::<u16>()?)
}

/// Register names: `(encoding, name)` to accesses, LLVM's set.
fn registers(package: &Package) -> Result<BTreeMap<(u16, String), u8>> {
    let mut out: BTreeMap<(u16, String), u8> = BTreeMap::new();
    for accessor in &package.accessors {
        let access = match accessor.instruction.as_str() {
            "A64.MRS" => READ,
            "A64.MSRregister" => WRITE,
            _ => continue,
        };
        for (fields, name) in expand(accessor)? {
            if LLVM_LACKS.contains(&name.as_str()) {
                continue;
            }
            let name = LLVM_RENAMES
                .iter()
                .find(|(arm, _)| *arm == name)
                .map_or(name, |(_, llvm)| (*llvm).to_owned());
            *out.entry((key(&fields, true)?, name)).or_default() |= access;
        }
    }
    for (name, encoding, access) in LLVM_REGISTERS {
        *out.entry((generic(encoding)?, (*name).to_owned()))
            .or_default() |= access;
    }
    // One name per encoding and access.
    let mut seen = BTreeMap::new();
    for ((encoding, name), access) in &out {
        let previous = seen.entry(*encoding).or_insert(0u8);
        if *previous & access != 0 {
            return Err(format!("two names for system register {encoding:#06x} ({name})").into());
        }
        *previous |= access;
    }
    Ok(out)
}

/// One system operation.
struct Operation {
    category: String,
    name: String,
    register: Register,
}

/// The operations of `SYS`, `SYSL` and `SYSP`, by instruction and
/// `op1:CRn:CRm:op2`.
fn operations(package: &Package) -> Result<BTreeMap<(&'static str, u16), Operation>> {
    // The instruction an accessor belongs to: the encoding with an alias of
    // its name (`A64.GICR` → `SYSL`); `A64.SYS`, … the encoding itself.
    let mut owners: BTreeMap<String, &'static str> = BTreeMap::new();
    for (_, encoding) in package.a64.encodings() {
        let Some((_, table)) = INSTRUCTIONS.iter().find(|(name, _)| *name == encoding.name) else {
            continue;
        };
        owners.insert(format!("A64.{table}"), table);
        for alias in &encoding.aliases {
            owners.insert(format!("A64.{}", alias.name), table);
        }
    }
    let mut out = BTreeMap::new();
    for accessor in &package.accessors {
        let Some(&table) = owners.get(&accessor.instruction) else {
            continue;
        };
        let kind = accessor.instruction.trim_start_matches("A64.");
        let category = CATEGORIES
            .iter()
            .find(|(name, _)| *name == kind)
            .map_or_else(|| title(table), |(_, variant)| (*variant).to_owned());
        for (fields, name) in expand(accessor)? {
            let register = LLVM_REGISTER
                .iter()
                .find(|(other, op, _)| *other == kind && *op == name)
                .map_or_else(|| Register::of(accessor), |(_, _, register)| *register);
            let operation = Operation {
                category: category.clone(),
                name: name.to_ascii_lowercase(),
                register,
            };
            if out
                .insert((table, key(&fields, false)?), operation)
                .is_some()
            {
                return Err(format!("two {table} operations at {name}").into());
            }
        }
    }
    for &(kind, op1, crn, crm, op2, name, register) in LLVM_OPERATIONS {
        let operation = Operation {
            category: title(kind),
            name: name.to_ascii_lowercase(),
            register,
        };
        out.insert(
            ("SYS", (op1 << 11) | (crn << 7) | (crm << 3) | op2),
            operation,
        );
    }
    Ok(out)
}

/// `SYSL` → `Sysl`.
fn title(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let mut chars = lower.chars();
    chars
        .next()
        .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
        .unwrap_or_default()
}

/// The `PSTATE` fields of `MSR (immediate)` by `op1:CRm:op2`: their name
/// and the `CRm` bits that are the value (those the field leaves free:
/// all of `CRm` for `SPSel`, `CRm<0>` for `ALLINT`).
fn pstate_fields(package: &Package) -> Result<BTreeMap<u16, (u64, String)>> {
    let mut values: BTreeMap<(u64, u64, String), Vec<u64>> = BTreeMap::new();
    for accessor in &package.accessors {
        if accessor.instruction != "A64.MSRimmediate" {
            continue;
        }
        for (fields, name) in expand(accessor)? {
            let field = |field: &str| {
                fields
                    .get(field)
                    .copied()
                    .ok_or_else(|| format!("PSTATE field {name} without {field}"))
            };
            let crms = values.entry((field("op1")?, field("op2")?, name.clone()));
            // A field whose `CRm` is not given has all of `CRm` as its value.
            crms.or_default().extend(
                fields
                    .get("CRm")
                    .map_or_else(|| (0..16).collect(), |crm| vec![*crm]),
            );
        }
    }
    let mut out = BTreeMap::new();
    for ((op1, op2, name), crms) in values {
        let first = crms.first().copied().unwrap_or_default();
        let mask = crms.iter().fold(0, |mask, crm| mask | (crm ^ first));
        for crm in crms {
            let key = u16::try_from((op1 << 7) | (crm << 3) | op2)?;
            if out.insert(key, (mask, name.clone())).is_some() {
                return Err(format!("two PSTATE fields at {name}").into());
            }
        }
    }
    Ok(out)
}

/// The `PSTATE` field table and its lookup.
fn pstate_table(package: &Package) -> Result<TokenStream> {
    let fields = pstate_fields(package)?;
    let rows = fields.iter().map(|(key, (mask, name))| {
        let (key, mask) = (lit(*key), lit(*mask));
        quote! { (#key, #mask, #name) }
    });
    let size = count(fields.len());
    Ok(quote! {
        /// `PSTATE` fields of `MSR (immediate)` by `op1:CRm:op2`, sorted:
        /// the `CRm` bits that are the value, the name.
        static PSTATE: [(u16, u8, &str); #size] = [#(#rows),*];

        /// The `PSTATE` field `MSR (immediate)` writes, as LLVM spells it
        /// (`SPSel`), and its value: the `CRm` bits the field leaves free.
        pub fn pstate(op1: u32, crm: u32, op2: u32) -> Option<(&'static str, u32)> {
            let key = (op1 << 7) | (crm << 3) | op2;
            let index = PSTATE.binary_search_by(|(other, _, _)| u32::from(*other).cmp(&key)).ok()?;
            PSTATE.get(index).map(|(_, mask, name)| (*name, crm & u32::from(*mask)))
        }
    })
}

/// The operation table of `table` and its lookup function `function`.
fn operation_table(
    operations: &BTreeMap<(&str, u16), Operation>,
    table: &str,
    function: &str,
) -> TokenStream {
    let rows: Vec<TokenStream> = operations
        .iter()
        .filter(|((other, _), _)| *other == table)
        .map(|((_, key), operation)| {
            let key = lit(*key);
            let category = format_ident!("{}", operation.category);
            let name = &operation.name;
            let register = operation.register.variant();
            quote! {
                (#key, Operation { category: SystemOp::#category, name: #name, register: #register })
            }
        })
        .collect();
    let size = count(rows.len());
    let constant = format_ident!("{}", table);
    let function = format_ident!("{function}");
    let doc = format!(" The `{table}` operation `op1:CRn:CRm:op2`, if it has a name.");
    let table_doc = format!(" `{table}` operations by `op1:CRn:CRm:op2`, sorted.");
    quote! {
        #[doc = #table_doc]
        static #constant: [(u16, Operation); #size] = [#(#rows),*];

        #[doc = #doc]
        pub fn #function(op1: u32, crn: u32, crm: u32, op2: u32) -> Option<Operation> {
            let key = (op1 << 11) | (crn << 7) | (crm << 3) | op2;
            let index = #constant.binary_search_by(|(other, _)| u32::from(*other).cmp(&key)).ok()?;
            #constant.get(index).map(|(_, operation)| *operation)
        }
    }
}

/// Generates the decoder's `sysreg.rs`.
pub fn generate(package: &Package) -> Result<GeneratedFile> {
    let registers = registers(package)?;
    let rows = registers.iter().map(|((encoding, name), access)| {
        let (encoding, access) = (lit(*encoding), lit(*access));
        quote! { (#encoding, #access, #name) }
    });
    let size = count(registers.len());
    let operations = operations(package)?;
    let tables = [("SYS", "sys"), ("SYSL", "sysl"), ("SYSP", "sysp")]
        .map(|(table, function)| operation_table(&operations, table, function));
    let pstate = pstate_table(package)?;
    let tokens = quote! {
        use crate::pseudocode::SystemOp;

        /// Read by `MRS` and `MRRS`.
        const READ: u8 = 1;
        /// Written by `MSR` and `MSRR`.
        const WRITE: u8 = 2;

        /// System registers, sorted: `op0:op1:CRn:CRm:op2`, the accesses the
        /// name is for, the name.
        static REGISTERS: [(u16, u8, &str); #size] = [#(#rows),*];

        fn register(encoding: u16, access: u8) -> Option<&'static str> {
            let start = REGISTERS.partition_point(|(other, _, _)| *other < encoding);
            REGISTERS
                .get(start..)?
                .iter()
                .take_while(|(other, _, _)| *other == encoding)
                .find(|(_, accesses, _)| accesses & access != 0)
                .map(|(_, _, name)| *name)
        }

        /// The name `MRS` and `MRRS` read the system register `encoding`
        /// (`op0:op1:CRn:CRm:op2`) by, as LLVM writes it.
        pub fn read(encoding: u16) -> Option<&'static str> {
            register(encoding, READ)
        }

        /// The name `MSR` and `MSRR` write the system register `encoding`
        /// by, as LLVM writes it.
        pub fn write(encoding: u16) -> Option<&'static str> {
            register(encoding, WRITE)
        }

        /// Whether a system operation takes a general register (`Xt`).
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Register {
            /// Never (`tlbi vmalle1`): LLVM writes `sys` when Rt is not 31.
            Never,
            /// Optionally (`tlbi vmalle1os`): written unless Rt is 31.
            Optional,
            /// Always (`tlbi vae1`), even as `xzr`.
            Always,
        }

        /// A named operation of `SYS`, `SYSL` or `SYSP`.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct Operation {
            /// What `SysOp`, `SysLOp` or `SysOp128` says it is.
            pub category: SystemOp,
            /// Its name, lower case as LLVM writes it (`civac`); empty for
            /// operations that are instructions of their own (`gcspushx`).
            pub name: &'static str,
            /// Whether it takes a register.
            pub register: Register,
        }

        #(#tables)*
        #pstate
    };
    Ok(GeneratedFile {
        path: output("sysreg"),
        notice: AARCHMRS_NOTICE,
        docs: vec![
            "System register names and system operations (`xtask/src/aarch64/sysreg.rs`)."
                .to_owned(),
        ],
        tokens,
    })
}
