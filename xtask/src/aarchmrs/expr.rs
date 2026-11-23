//! Expressions (`AST.*` nodes) and bit patterns (`Values.Value`).

use std::fmt;

use serde::Deserialize;

/// A bit pattern such as `'01x'`: most significant bit first, `x` for a bit
/// that may take either value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct Pattern(String);

impl Pattern {
    /// The pattern's characters without the quotes, e.g. `01x`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Number of bits.
    pub fn width(&self) -> u32 {
        // Patterns are ASCII and at most 64 characters long (checked on
        // construction).
        u32::try_from(self.0.len()).unwrap_or(u32::MAX)
    }

    /// The bits given as `0` or `1`, least significant bit at position 0.
    pub fn mask(&self) -> u64 {
        self.bits(|c| c != 'x')
    }

    /// The bits given as `1`.
    pub fn value(&self) -> u64 {
        self.bits(|c| c == '1')
    }

    /// Whether `value` (the pattern's width, least significant bit first)
    /// matches.
    pub fn matches(&self, value: u64) -> bool {
        value & self.mask() == self.value()
    }

    fn bits(&self, set: impl Fn(char) -> bool) -> u64 {
        self.0
            .chars()
            .fold(0, |bits, c| (bits << 1) | u64::from(set(c)))
    }
}

impl TryFrom<String> for Pattern {
    type Error = String;

    /// Accepts `'01x'` with the quotes AARCHMRS writes, or a bare `01x`.
    fn try_from(text: String) -> Result<Self, String> {
        let bits = text
            .strip_prefix('\'')
            .and_then(|rest| rest.strip_suffix('\''))
            .unwrap_or(&text);
        if bits.len() > 64 || !bits.chars().all(|c| matches!(c, '0' | '1' | 'x')) {
            return Err(format!("`{text}` is not a bit pattern"));
        }
        Ok(Self(bits.to_owned()))
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "'{}'", self.0)
    }
}

/// A condition or value expression, as AARCHMRS writes ASL expressions.
///
/// The variants are the node types the A64 instructions, the assembly rules,
/// `Features.json` and the A64 system accessors use; anything else is a
/// parse error, so a schema change is noticed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawExpr")]
pub enum Expr {
    /// `TRUE`/`FALSE` (`AST.Bool`).
    Bool(bool),
    /// An integer (`AST.Integer`).
    Integer(i64),
    /// A name: an encoding field, a feature or a variable (`AST.Identifier`).
    Identifier(String),
    /// A bit pattern (`Values.Value`), e.g. `'11111'`.
    Bits(Pattern),
    /// `{a, b}`, the right operand of `IN` (`AST.Set`).
    Set(Vec<Expr>),
    /// `left op right` (`AST.BinaryOp`).
    Binary {
        /// The operator.
        op: BinaryOp,
        /// Left operand.
        left: Box<Expr>,
        /// Right operand.
        right: Box<Expr>,
    },
    /// `!operand` (`AST.UnaryOp`).
    Not(Box<Expr>),
    /// `name(arguments)` (`AST.Function`), e.g.
    /// `IsFeatureImplemented(FEAT_SVE)`.
    Call {
        /// The function.
        name: String,
        /// The arguments.
        arguments: Vec<Expr>,
    },
    /// `base[arguments]`, a bit index or slice (`AST.SquareOp`).
    Index {
        /// The indexed value.
        base: Box<Expr>,
        /// The indices.
        arguments: Vec<Expr>,
    },
    /// `a.b.c` (`AST.DotAtom`), e.g. `PMU.PMDEVID.EXTPMN`.
    Dot(Vec<Expr>),
    /// A system register field (`Types.Field`), e.g.
    /// `ID_AA64MMFR0_EL1.TGran4`.
    Field {
        /// The register.
        register: String,
        /// The field.
        field: String,
    },
    /// A string (`Types.String`).
    String(String),
}

/// The binary operators AARCHMRS uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOp {
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `&&`
    And,
    /// `||`
    Or,
    /// `IN`: the left operand matches one of the set's patterns.
    In,
    /// `+`
    Add,
    /// `::`, bit concatenation.
    Concat,
    /// `==>`, implication (feature constraints).
    Implies,
    /// `<=>`, equivalence (feature constraints).
    Iff,
}

impl BinaryOp {
    /// The operator as AARCHMRS writes it.
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::And => "&&",
            Self::Or => "||",
            Self::In => "IN",
            Self::Add => "+",
            Self::Concat => "::",
            Self::Implies => "==>",
            Self::Iff => "<=>",
        }
    }

    fn parse(symbol: &str) -> Option<Self> {
        Some(match symbol {
            "==" => Self::Eq,
            "!=" => Self::Ne,
            "<" => Self::Lt,
            ">" => Self::Gt,
            ">=" => Self::Ge,
            "&&" => Self::And,
            "||" => Self::Or,
            "IN" => Self::In,
            "+" => Self::Add,
            "::" => Self::Concat,
            "==>" => Self::Implies,
            "<=>" => Self::Iff,
            _ => return None,
        })
    }
}

impl Expr {
    /// Calls `visit` on this expression and every subexpression, parents
    /// first.
    pub fn walk<'a>(&'a self, visit: &mut impl FnMut(&'a Self)) {
        visit(self);
        match self {
            Self::Bool(_)
            | Self::Integer(_)
            | Self::Identifier(_)
            | Self::Bits(_)
            | Self::Field { .. }
            | Self::String(_) => {}
            Self::Set(items)
            | Self::Dot(items)
            | Self::Call {
                arguments: items, ..
            } => {
                for item in items {
                    item.walk(visit);
                }
            }
            Self::Binary { left, right, .. } => {
                left.walk(visit);
                right.walk(visit);
            }
            Self::Not(operand) => operand.walk(visit),
            Self::Index { base, arguments } => {
                base.walk(visit);
                for argument in arguments {
                    argument.walk(visit);
                }
            }
        }
    }

    /// The feature named by `IsFeatureImplemented(FEAT_X)`, if this is such a
    /// call.
    pub fn feature_check(&self) -> Option<&str> {
        let Self::Call { name, arguments } = self else {
            return None;
        };
        match (name.as_str(), arguments.as_slice()) {
            ("IsFeatureImplemented", [Self::Identifier(feature)]) => Some(feature),
            _ => None,
        }
    }

    /// Every feature this expression checks with `IsFeatureImplemented`, in
    /// order of appearance, with repeats.
    pub fn features(&self) -> Vec<&str> {
        let mut features = Vec::new();
        self.walk(&mut |expr| features.extend(expr.feature_check()));
        features
    }
}

impl fmt::Display for Expr {
    /// ASL-like text, fully parenthesised.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = |f: &mut fmt::Formatter<'_>, items: &[Self], separator: &str| {
            items.iter().enumerate().try_for_each(|(i, item)| {
                if i > 0 {
                    f.write_str(separator)?;
                }
                write!(f, "{item}")
            })
        };
        match self {
            Self::Bool(value) => write!(f, "{}", if *value { "TRUE" } else { "FALSE" }),
            Self::Integer(value) => write!(f, "{value}"),
            Self::Identifier(name) | Self::String(name) => f.write_str(name),
            Self::Bits(pattern) => write!(f, "{pattern}"),
            Self::Set(items) => {
                f.write_str("{")?;
                list(f, items, ", ")?;
                f.write_str("}")
            }
            Self::Binary { op, left, right } => write!(f, "({left} {} {right})", op.symbol()),
            Self::Not(operand) => write!(f, "!{operand}"),
            Self::Call { name, arguments } => {
                write!(f, "{name}(")?;
                list(f, arguments, ", ")?;
                f.write_str(")")
            }
            Self::Index { base, arguments } => {
                write!(f, "{base}[")?;
                list(f, arguments, ", ")?;
                f.write_str("]")
            }
            Self::Dot(items) => list(f, items, "."),
            Self::Field { register, field } => write!(f, "{register}.{field}"),
        }
    }
}

/// An expression as the JSON writes it.
#[derive(Deserialize)]
#[serde(tag = "_type")]
enum RawExpr {
    #[serde(rename = "AST.Bool")]
    Bool { value: bool },
    #[serde(rename = "AST.Integer")]
    Integer { value: i64 },
    #[serde(rename = "AST.Identifier")]
    Identifier { value: String },
    #[serde(rename = "Values.Value")]
    Value { value: Pattern },
    #[serde(rename = "AST.Set")]
    Set { values: Vec<Expr> },
    #[serde(rename = "AST.BinaryOp")]
    Binary {
        op: String,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    #[serde(rename = "AST.UnaryOp")]
    Unary { op: String, expr: Box<Expr> },
    #[serde(rename = "AST.Function")]
    Function { name: String, arguments: Vec<Expr> },
    #[serde(rename = "AST.SquareOp")]
    Square {
        var: Box<Expr>,
        arguments: Vec<Expr>,
    },
    #[serde(rename = "AST.DotAtom")]
    Dot { values: Vec<Expr> },
    #[serde(rename = "Types.Field")]
    Field { value: RawField },
    #[serde(rename = "Types.String")]
    String { value: String },
}

#[derive(Deserialize)]
struct RawField {
    name: String,
    field: String,
}

impl TryFrom<RawExpr> for Expr {
    type Error = String;

    fn try_from(raw: RawExpr) -> Result<Self, String> {
        Ok(match raw {
            RawExpr::Bool { value } => Self::Bool(value),
            RawExpr::Integer { value } => Self::Integer(value),
            RawExpr::Identifier { value } => Self::Identifier(value),
            RawExpr::Value { value } => Self::Bits(value),
            RawExpr::Set { values } => Self::Set(values),
            RawExpr::Binary { op, left, right } => Self::Binary {
                op: BinaryOp::parse(&op).ok_or_else(|| format!("unknown operator `{op}`"))?,
                left,
                right,
            },
            RawExpr::Unary { op, expr } => match op.as_str() {
                "!" => Self::Not(expr),
                _ => return Err(format!("unknown unary operator `{op}`")),
            },
            RawExpr::Function { name, arguments } => Self::Call { name, arguments },
            RawExpr::Square { var, arguments } => Self::Index {
                base: var,
                arguments,
            },
            RawExpr::Dot { values } => Self::Dot(values),
            RawExpr::Field { value } => Self::Field {
                register: value.name,
                field: value.field,
            },
            RawExpr::String { value } => Self::String(value),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

    use super::{BinaryOp, Expr, Pattern};

    #[test]
    fn patterns_split_into_mask_and_value() {
        let pattern = Pattern::try_from("'1x0'".to_owned()).unwrap();
        assert_eq!(
            (pattern.mask(), pattern.value(), pattern.width()),
            (0b101, 0b100, 3)
        );
        assert!(pattern.matches(0b110) && pattern.matches(0b100) && !pattern.matches(0b101));
        assert!(Pattern::try_from("'012'".to_owned()).is_err());
    }

    #[test]
    fn parses_conditions_and_rejects_unknown_operators() {
        let json = r#"{"_type":"AST.BinaryOp","op":"&&",
            "left":{"_type":"AST.Function","name":"IsFeatureImplemented","parameters":[],
                    "arguments":[{"_type":"AST.Identifier","value":"FEAT_SVE"}]},
            "right":{"_type":"AST.BinaryOp","op":"!=",
                     "left":{"_type":"AST.Identifier","value":"Rm"},
                     "right":{"_type":"Values.Value","meaning":null,"value":"'11111'"}}}"#;
        let expr: Expr = serde_json::from_str(json).unwrap();
        assert_eq!(
            expr.to_string(),
            "(IsFeatureImplemented(FEAT_SVE) && (Rm != '11111'))"
        );
        assert_eq!(expr.features(), ["FEAT_SVE"]);
        assert!(matches!(
            expr,
            Expr::Binary {
                op: BinaryOp::And,
                ..
            }
        ));
        let unknown = json.replace("\"&&\"", "\"^^\"");
        assert!(serde_json::from_str::<Expr>(&unknown).is_err());
    }
}
