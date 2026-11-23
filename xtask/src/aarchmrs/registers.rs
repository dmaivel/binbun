//! A64 system instruction accessors from `Registers.json`: the names `MRS`,
//! `MSR`, `SYS` aliases (`DC`, `IC`, `AT`, `TLBI`, …) and friends give to
//! `op0:op1:CRn:CRm:op2` encodings.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::Error as _;
use serde_json::value::RawValue as RawJson;

use crate::aarchmrs::expr::{Expr, Pattern};
use crate::aarchmrs::instructions::Range;

/// One way an A64 instruction reaches a register or operation
/// (`Accessors.SystemAccessor` or `Accessors.SystemAccessorArray`).
#[derive(Debug, Clone)]
pub struct SystemAccessor {
    /// The register (or register array, e.g. `DBGBVR<n>_EL1`) it belongs to.
    pub register: String,
    /// The instruction, e.g. `A64.MRS`, `A64.MSRregister`, `A64.TLBI`.
    pub instruction: String,
    /// When the accessor exists, e.g. `IsFeatureImplemented(FEAT_VHE)`.
    pub condition: Expr,
    /// The assembler name and the encoding of the instruction's fields.
    pub encodings: Vec<AccessorEncoding>,
    /// For arrays: the index variable and its ranges.
    pub index: Option<AccessorIndex>,
    /// For a system operation (`TLBI VAE1`), the conditions of its field
    /// layouts (`fieldsets`): it has an `Xt` operand when one holds, none
    /// (`TLBI VMALLE1`) when the list is empty. Empty for registers, whose
    /// layouts are not read.
    pub fieldsets: Vec<Expr>,
}

/// The accessor instructions of registers, as opposed to operations.
const REGISTER_ACCESSES: &[&str] = &[
    "A64.MRS",
    "A64.MSRregister",
    "A64.MRRS",
    "A64.MSRRregister",
    "A64.MSRimmediate",
];

/// An accessor's name in assembly and its field values (`Encoding`).
#[derive(Debug, Clone)]
pub struct AccessorEncoding {
    /// Assembler name, e.g. `TTBR0_EL1` or `DBGBVR<m>_EL1`.
    pub asm_value: Option<String>,
    /// Value of each instruction field (`op0`, `op1`, `CRn`, `CRm`, `op2`).
    pub fields: BTreeMap<String, AccessorValue>,
}

/// The value of one field in an [`AccessorEncoding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessorValue {
    /// Fixed bits (`Values.Value`).
    Bits(Pattern),
    /// Bits of the index variable (`Values.EquationValue`), e.g. `m[3:0]`.
    Variable {
        /// The index variable.
        name: String,
        /// The bits taken from it, most significant range first.
        slices: Vec<Range>,
    },
    /// A concatenation of bits and index bits (`Values.Group`), as text, e.g.
    /// `'011':p[3]`.
    Concatenation(String),
}

/// The index of an accessor array.
#[derive(Debug, Clone)]
pub struct AccessorIndex {
    /// The variable, e.g. `n`.
    pub variable: String,
    /// The values it takes.
    pub ranges: Vec<Range>,
}

#[derive(Deserialize)]
struct RawRegister<'a> {
    #[serde(default)]
    name: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default, borrow)]
    accessors: Option<Vec<&'a RawJson>>,
    #[serde(default, borrow)]
    fieldsets: Option<Vec<&'a RawJson>>,
}

#[derive(Deserialize)]
struct RawFieldset {
    condition: Expr,
}

#[derive(Deserialize)]
struct RawAccessorKind {
    #[serde(rename = "_type")]
    kind: String,
}

#[derive(Deserialize)]
struct RawAccessor {
    name: String,
    condition: Expr,
    encoding: Vec<RawEncoding>,
    #[serde(default)]
    index_variable: Option<String>,
    #[serde(default)]
    indexes: Option<Vec<Range>>,
}

#[derive(Deserialize)]
struct RawEncoding {
    asmvalue: Option<String>,
    encodings: BTreeMap<String, RawAccessorValue>,
}

#[derive(Deserialize)]
#[serde(tag = "_type")]
enum RawAccessorValue {
    #[serde(rename = "Values.Value")]
    Value { value: Pattern },
    #[serde(rename = "Values.EquationValue")]
    Equation { value: String, slice: Vec<Range> },
    #[serde(rename = "Values.Group")]
    Group { value: String },
}

/// Parses `Registers.json`, keeping the system accessors of AArch64
/// registers. Other registers' accessors (memory-mapped, external debug,
/// AArch32) are skipped without being materialised.
///
/// # Errors
///
/// If the text is not JSON or an AArch64 system accessor does not follow the
/// modelled schema.
pub fn parse(json: &[u8]) -> Result<Vec<SystemAccessor>, serde_json::Error> {
    let registers: Vec<RawRegister<'_>> = serde_json::from_slice(json)?;
    let mut out = Vec::new();
    for register in registers {
        if register.state.as_deref() != Some("AArch64") {
            continue;
        }
        let first = out.len();
        for accessor in register.accessors.unwrap_or_default() {
            let kind: RawAccessorKind = serde_json::from_str(accessor.get())?;
            let array = match kind.kind.as_str() {
                "Accessors.SystemAccessor" => false,
                "Accessors.SystemAccessorArray" => true,
                _ => continue,
            };
            let raw: RawAccessor = serde_json::from_str(accessor.get())?;
            let index = match (array, raw.index_variable, raw.indexes) {
                (false, _, _) => None,
                (true, Some(variable), Some(ranges)) => Some(AccessorIndex { variable, ranges }),
                (true, _, _) => {
                    return Err(serde_json::Error::custom(format!(
                        "accessor array {} of {} has no index",
                        raw.name, register.name
                    )));
                }
            };
            out.push(SystemAccessor {
                register: register.name.clone(),
                instruction: raw.name,
                condition: raw.condition,
                encodings: raw
                    .encoding
                    .into_iter()
                    .map(|encoding| AccessorEncoding {
                        asm_value: encoding.asmvalue,
                        fields: encoding
                            .encodings
                            .into_iter()
                            .map(|(field, value)| (field, value.into()))
                            .collect(),
                    })
                    .collect(),
                index,
                fieldsets: Vec::new(),
            });
        }
        let accessors = out.get_mut(first..).unwrap_or_default();
        if accessors
            .iter()
            .any(|accessor| !REGISTER_ACCESSES.contains(&accessor.instruction.as_str()))
        {
            let fieldsets = register
                .fieldsets
                .iter()
                .flatten()
                .map(|fieldset| {
                    serde_json::from_str::<RawFieldset>(fieldset.get()).map(|raw| raw.condition)
                })
                .collect::<Result<Vec<_>, _>>()?;
            for accessor in accessors {
                accessor.fieldsets.clone_from(&fieldsets);
            }
        }
    }
    Ok(out)
}

impl From<RawAccessorValue> for AccessorValue {
    fn from(raw: RawAccessorValue) -> Self {
        match raw {
            RawAccessorValue::Value { value } => Self::Bits(value),
            RawAccessorValue::Equation { value, slice } => Self::Variable {
                name: value,
                slices: slice,
            },
            RawAccessorValue::Group { value } => Self::Concatenation(value),
        }
    }
}
