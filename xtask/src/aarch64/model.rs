//! The A64 encodings as the decoder sees them: fixed bits, field-condition
//! exclusions, features.

use std::collections::BTreeSet;

use xtask::aarchmrs::{Encodeset, Expr, Features, Group, Instruction, Package};

use super::cond;
use super::cube::{Cube, cubes};
use crate::Result;

/// One A64 encoding.
#[derive(Debug)]
pub struct Encoding<'a> {
    pub instruction: &'a Instruction,
    /// Groups from the root down.
    pub groups: Vec<&'a Group>,
    /// Bits every word of the encoding has: AARCHMRS's fixed bits without
    /// the should-be bits, narrowed by field conditions that allow a single
    /// cube (`sz == '0'`).
    pub fixed: Cube,
    /// Words within `fixed` that the field conditions of the encoding and its
    /// groups exclude (`Rm != '11111'`).
    pub excluded: Vec<Cube>,
    /// The should-be bits and the values they should have.
    pub should_be: Cube,
    /// Features the condition names (the nearest group's if the encoding's
    /// own names none), in order of appearance.
    pub features: Vec<&'a str>,
    /// Whether the encoding needs a feature of an unannounced architecture
    /// version (`vFATAp*`).
    pub fat: bool,
}

impl<'a> Encoding<'a> {
    pub fn name(&self) -> &'a str {
        &self.instruction.name
    }

    /// Lowest bit and width of the field `name`.
    pub fn field(&self, name: &str) -> Option<(u32, u32)> {
        cond::field(&self.instruction.encoding, name)
    }
}

/// Fixed bits and should-be bits (with their specified values) of an
/// encoding set.
fn fixed_bits(encoding: &Encodeset) -> Result<(Cube, Cube)> {
    let mut mask = 0u32;
    let mut value = 0u32;
    let mut should_be = 0u32;
    let mut should_be_value = 0u32;
    let mut covered = 0u32;
    for field in &encoding.fields {
        let bits = |bits: u64| u32::try_from(bits << field.start);
        let range = bits((1 << field.width) - 1)?;
        if covered & range != 0 {
            return Err(format!("{:?}: overlapping fields", field.name).into());
        }
        covered |= range;
        let soft = bits(field.should_be_mask.value())?;
        mask |= bits(field.value.mask())? & !soft;
        value |= bits(field.value.value())? & !soft;
        should_be |= soft;
        should_be_value |= bits(field.value.value())? & soft;
    }
    if encoding.width != 32 || covered != u32::MAX {
        return Err("an A64 encoding does not describe all 32 bits".into());
    }
    Ok((
        Cube::new(mask, value),
        Cube::new(should_be, should_be_value),
    ))
}

/// Features whose architecture version is unannounced (`vFATAp*`).
pub fn fat_features(features: &Features) -> BTreeSet<&str> {
    features
        .parameters
        .iter()
        .filter(|p| !p.is_version())
        .filter(|p| {
            features
                .versions(&p.name)
                .iter()
                .any(|v| v.starts_with("vFAT"))
        })
        .map(|p| p.name.as_str())
        .collect()
}

/// Every A64 encoding, in tree order.
pub fn collect(package: &Package) -> Result<Vec<Encoding<'_>>> {
    let fat = fat_features(&package.features);
    let every_feature = |_: &str| true;
    let released = |name: &str| !fat.contains(name);
    package
        .a64
        .encodings()
        .into_iter()
        .map(|(groups, instruction)| {
            let context =
                |error: Box<dyn std::error::Error>| format!("{}: {error}", instruction.name);
            let (mut fixed, should_be) = fixed_bits(&instruction.encoding).map_err(context)?;
            let mut excluded = Vec::new();
            let mut fat_only = false;
            let conditions = groups
                .iter()
                .map(|g| (&g.condition, &g.encoding))
                .chain([(&instruction.condition, &instruction.encoding)]);
            for (condition, encoding) in conditions {
                let rejected =
                    cond::rejected(condition, encoding, &every_feature, fixed).map_err(context)?;
                let allowed = cubes(fixed, cond::bits_read(condition, encoding)?, |word| {
                    !rejected.iter().any(|c| c.contains(word))
                })?;
                // Under released features only, a FAT-only encoding's
                // condition rejects every word.
                fat_only |= !fixed.exceeds(
                    &cond::rejected(condition, encoding, &released, fixed).map_err(context)?,
                );
                match allowed.as_slice() {
                    [] => {
                        return Err(
                            format!("{}: no word satisfies {condition}", instruction.name).into(),
                        );
                    }
                    [only] => fixed = fixed.intersection(*only),
                    _ => excluded.extend(rejected),
                }
            }
            // Groups and encodings repeat each other's conditions
            // (`immh != '0000'`).
            excluded.sort_unstable();
            excluded.dedup();
            Ok(Encoding {
                instruction,
                features: features(instruction, &groups),
                groups,
                fixed,
                excluded,
                should_be,
                fat: fat_only,
            })
        })
        .collect()
}

/// The features `condition` names, without repeats.
fn named(condition: &Expr) -> Vec<&str> {
    let mut names: Vec<&str> = Vec::new();
    for name in condition.features() {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

fn features<'a>(instruction: &'a Instruction, groups: &[&'a Group]) -> Vec<&'a str> {
    let own = named(&instruction.condition);
    if !own.is_empty() {
        return own;
    }
    groups
        .iter()
        .rev()
        .map(|g| named(&g.condition))
        .find(|names| !names.is_empty())
        .unwrap_or_default()
}
