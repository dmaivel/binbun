//! XED's nonterminals in a form the generators can evaluate.
//!
//! A rule's pattern is reduced to field constraints (`MODE=2`, `REXW!=0`,
//! literal captures such as `MOD[0b11]`) and nonterminal calls; its bindings
//! are parsed operands. Rules of one nonterminal are disjoint in XED (no
//! priority), which [`Grammar::evaluate`] checks for the points it visits.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use binbun_xed::StateMacros;
use binbun_xed::nonterminals::Nonterminal;
use binbun_xed::operands::{self, Operand, Value, Word};
use binbun_xed::pattern::{Bit, Pattern, Test, Token};

use crate::Result;

/// A required field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Condition<'a> {
    pub field: &'a str,
    pub test: Test,
    pub value: u64,
}

impl Condition<'_> {
    pub fn holds(self, value: u64) -> bool {
        match self.test {
            Test::Eq => value == self.value,
            Test::Ne => value != self.value,
        }
    }
}

/// One rule of a nonterminal.
#[derive(Debug)]
pub struct Rule<'a> {
    pub line: u32,
    /// `None` for the `otherwise` rule.
    pub conditions: Option<Vec<Condition<'a>>>,
    /// Nonterminals the pattern calls, in order.
    pub calls: Vec<&'a str>,
    /// Whether the pattern matches literal bits or the bindings restart the
    /// nonterminal (`XED_RESET`): only prefix and spine nonterminals do,
    /// whose bytes the length decoder consumes.
    pub scans_bytes: bool,
    /// Field bindings and outputs.
    pub bindings: Vec<Operand<'a>>,
}

impl Rule<'_> {
    /// The number bound to `field`, if the rule binds one.
    pub fn binds(&self, field: &str) -> Option<u64> {
        self.bindings
            .iter()
            .find(|op| op.name == field)
            .and_then(|op| {
                if let Value::Number(n) = op.value {
                    Some(n)
                } else {
                    None
                }
            })
    }
}

/// Every nonterminal by name.
#[derive(Debug)]
pub struct Grammar<'a> {
    rules: HashMap<&'a str, Vec<Rule<'a>>>,
}

impl<'a> Grammar<'a> {
    pub fn new(nonterminals: &'a [Nonterminal<'a>], macros: &StateMacros<'a>) -> Result<Self> {
        let mut rules = HashMap::new();
        for nt in nonterminals {
            let parsed = nt
                .rules
                .iter()
                .map(|rule| -> Result<Rule<'a>> {
                    let words = operands::parse(rule.line, rule.bindings, macros)?;
                    let mut scans_bytes = words.iter().any(|word| matches!(word, Word::Reset));
                    let bindings = words
                        .into_iter()
                        .filter_map(|word| match word {
                            Word::Operand(operand) => Some(operand),
                            Word::Reset => None,
                        })
                        .collect();
                    let (conditions, calls) = match &rule.pattern {
                        Pattern::Otherwise => (None, Vec::new()),
                        Pattern::Tokens(tokens) => {
                            scans_bytes |= tokens.iter().any(|t| matches!(t, Token::Bits(_)));
                            let (conditions, calls) = conditions(tokens);
                            (Some(conditions), calls)
                        }
                    };
                    Ok(Rule {
                        line: rule.line,
                        conditions,
                        calls,
                        scans_bytes,
                        bindings,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            rules.insert(nt.name, parsed);
        }
        Ok(Self { rules })
    }

    pub fn rules(&self, nt: &str) -> Result<&[Rule<'a>]> {
        self.rules
            .get(nt)
            .map(Vec::as_slice)
            .ok_or_else(|| format!("unknown nonterminal `{nt}`").into())
    }

    /// Every value a rule binds `field` to; an error if some rule binds it
    /// to anything but a constant.
    pub fn bound_values(&self, field: &str) -> Result<BTreeSet<u64>> {
        let mut values = BTreeSet::new();
        for (nt, rules) in &self.rules {
            for rule in rules {
                for binding in rule.bindings.iter().filter(|b| b.name == field) {
                    let Value::Number(n) = binding.value else {
                        return Err(format!(
                            "{nt} (line {}) binds {field} to {:?}",
                            rule.line, binding.value
                        )
                        .into());
                    };
                    values.insert(n);
                }
            }
        }
        Ok(values)
    }

    /// Names of the nonterminals with a rule that binds `field`.
    pub fn setters(&self, field: &str) -> BTreeSet<&'a str> {
        self.rules
            .iter()
            .filter(|(_, rules)| {
                rules
                    .iter()
                    .any(|rule| rule.bindings.iter().any(|op| op.name == field))
            })
            .map(|(&name, _)| name)
            .collect()
    }

    /// The largest constant any rule stores in each field.
    pub fn largest_constants(&self) -> BTreeMap<&'a str, u64> {
        let mut largest: BTreeMap<&'a str, u64> = BTreeMap::new();
        for operand in self
            .rules
            .values()
            .flatten()
            .flat_map(|rule| &rule.bindings)
        {
            if let Value::Number(n) = operand.value {
                let entry = largest.entry(operand.name).or_insert(0);
                *entry = (*entry).max(n);
            }
        }
        largest
    }

    /// The rule of `nt` that applies when fields have the values in `env`:
    /// the one whose conditions hold, else the `otherwise` rule, else none.
    /// Fails if a condition reads a field missing from `env`, or if two
    /// rules apply.
    pub fn evaluate(&self, nt: &str, env: &BTreeMap<&str, u64>) -> Result<Option<&Rule<'a>>> {
        let rules = self.rules(nt)?;
        let mut found: Option<&Rule<'a>> = None;
        for rule in rules {
            let Some(conditions) = &rule.conditions else {
                continue;
            };
            let mut holds = true;
            for condition in conditions {
                let value = env.get(condition.field).ok_or_else(|| {
                    format!(
                        "{nt} (line {}) depends on {}, which is not known here",
                        rule.line, condition.field
                    )
                })?;
                holds &= condition.holds(*value);
            }
            if holds {
                if let Some(other) = found {
                    return Err(format!(
                        "{nt}: rules on lines {} and {} overlap",
                        other.line, rule.line
                    )
                    .into());
                }
                found = Some(rule);
            }
        }
        Ok(found.or_else(|| rules.iter().find(|rule| rule.conditions.is_none())))
    }
}

/// The conditions and nonterminal calls of a pattern. A capture whose bits
/// are all literal is a condition too (`MOD[0b11]` means `MOD=3`).
pub fn conditions<'a>(tokens: &[Token<'a>]) -> (Vec<Condition<'a>>, Vec<&'a str>) {
    let mut conditions = Vec::new();
    let mut calls = Vec::new();
    for token in tokens {
        match token {
            Token::Constraint(c) => conditions.push(Condition {
                field: c.field,
                test: c.test,
                value: c.value,
            }),
            Token::Capture { field, bits } => {
                if let Some(value) = literal(bits) {
                    conditions.push(Condition {
                        field,
                        test: Test::Eq,
                        value,
                    });
                }
            }
            Token::Nonterminal(name) => calls.push(*name),
            Token::Bits(_) => {}
        }
    }
    (conditions, calls)
}

/// The value of `bits` if none is variable.
pub fn literal(bits: &[Bit]) -> Option<u64> {
    bits.iter().try_fold(0u64, |value, bit| match bit {
        Bit::Zero => Some(value << 1),
        Bit::One => Some((value << 1) | 1),
        Bit::Var(_) => None,
    })
}
