//! The feature model (`Features.json`).

use serde::Deserialize;
use serde::de::Error as _;

use crate::aarchmrs::expr::{BinaryOp, Expr};

/// The architecture parameters and the constraints between them.
#[derive(Debug, Clone)]
pub struct Features {
    /// Every parameter: `FEAT_*` features and architecture versions
    /// (`v8Ap0` … `v9Ap8`, `vFATAp0` …).
    pub parameters: Vec<Parameter>,
    /// Constraints not attached to one parameter.
    pub constraints: Vec<Expr>,
}

/// A boolean architecture parameter (`Parameters.Boolean`).
#[derive(Debug, Clone)]
pub struct Parameter {
    /// Name, e.g. `FEAT_SVE2` or `v9Ap0`.
    pub name: String,
    /// Title, if any.
    pub title: Option<String>,
    /// Constraints, e.g. `FEAT_SVE2 ==> v9Ap0` and `FEAT_SVE2 ==> FEAT_SVE`.
    pub constraints: Vec<Expr>,
}

#[derive(Deserialize)]
struct RawFeatures {
    parameters: Vec<RawParameter>,
    constraints: Vec<Expr>,
}

#[derive(Deserialize)]
struct RawParameter {
    #[serde(rename = "_type")]
    kind: String,
    name: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    constraints: Vec<Expr>,
}

/// Parses `Features.json`.
///
/// # Errors
///
/// If the text is not JSON or does not follow the modelled schema (every
/// parameter boolean).
pub fn parse(json: &[u8]) -> Result<Features, serde_json::Error> {
    let raw: RawFeatures = serde_json::from_slice(json)?;
    let parameters = raw
        .parameters
        .into_iter()
        .map(|parameter| {
            if parameter.kind != "Parameters.Boolean" {
                return Err(serde_json::Error::custom(format!(
                    "parameter {} is a {}",
                    parameter.name, parameter.kind
                )));
            }
            Ok(Parameter {
                name: parameter.name,
                title: parameter.title,
                constraints: parameter.constraints,
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(Features {
        parameters,
        constraints: raw.constraints,
    })
}

impl Parameter {
    /// Whether this is an architecture version such as `v9Ap4` or `vFATAp1`
    /// rather than a feature.
    pub fn is_version(&self) -> bool {
        !self.name.starts_with("FEAT_")
    }

    /// The parameters this one directly implies: the right-hand identifiers
    /// of its `NAME ==> OTHER` constraints.
    pub fn implies(&self) -> impl Iterator<Item = &str> {
        self.constraints.iter().filter_map(move |constraint| {
            let Expr::Binary {
                op: BinaryOp::Implies,
                left,
                right,
            } = constraint
            else {
                return None;
            };
            let (Expr::Identifier(left), Expr::Identifier(right)) = (left.as_ref(), right.as_ref())
            else {
                return None;
            };
            (*left == self.name).then_some(right.as_str())
        })
    }
}

impl Features {
    /// The parameter named `name`.
    pub fn get(&self, name: &str) -> Option<&Parameter> {
        self.parameters
            .iter()
            .find(|parameter| parameter.name == name)
    }

    /// The architecture versions `name` implies, directly or through other
    /// features.
    pub fn versions(&self, name: &str) -> Vec<&str> {
        let mut seen = vec![name];
        let mut pending = vec![name];
        let mut versions = Vec::new();
        while let Some(current) = pending.pop() {
            let Some(parameter) = self.get(current) else {
                continue;
            };
            if parameter.is_version() {
                versions.push(parameter.name.as_str());
            }
            for implied in parameter.implies() {
                if !seen.contains(&implied) {
                    seen.push(implied);
                    pending.push(implied);
                }
            }
        }
        versions.sort_unstable();
        versions
    }
}
