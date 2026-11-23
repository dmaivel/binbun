//! The instruction tree (`Instructions.json`): groups, encodings, aliases,
//! encoding sets and assembly syntax.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::Error as _;
use serde_json::value::RawValue as RawJson;

use crate::aarchmrs::Version;
use crate::aarchmrs::expr::{Expr, Pattern};

/// What the generator uses of `Instructions.json`.
#[derive(Debug, Clone)]
pub struct Instructions {
    /// The release.
    pub version: Version,
    /// The A64 instruction set.
    pub a64: InstructionSet,
    /// Assembly rules by id, for all instruction sets.
    pub assembly_rules: BTreeMap<String, AssemblyRule>,
}

#[derive(Deserialize)]
struct RawInstructions<'a> {
    #[serde(rename = "_meta")]
    meta: RawFileMeta,
    #[serde(borrow)]
    instructions: Vec<&'a RawJson>,
    assembly_rules: BTreeMap<String, AssemblyRule>,
}

#[derive(Deserialize)]
struct RawFileMeta {
    version: Version,
}

/// Just the name of an instruction set, so A32 and T32 are skipped without
/// being materialised.
#[derive(Deserialize)]
struct SetName {
    name: String,
}

/// Parses `Instructions.json`. Returns `None` if it has no A64 set.
///
/// # Errors
///
/// If the text is not JSON or does not follow the modelled schema.
pub fn parse(json: &[u8]) -> Result<Option<Instructions>, serde_json::Error> {
    let raw: RawInstructions<'_> = serde_json::from_slice(json)?;
    for set in raw.instructions {
        if serde_json::from_str::<SetName>(set.get())?.name != "A64" {
            continue;
        }
        let node: RawNode = serde_json::from_str(set.get())?;
        return Ok(Some(Instructions {
            version: raw.meta.version,
            a64: node
                .into_instruction_set()
                .map_err(serde_json::Error::custom)?,
            assembly_rules: raw.assembly_rules,
        }));
    }
    Ok(None)
}

/// An instruction set (`Instruction.InstructionSet`), e.g. A64.
#[derive(Debug, Clone)]
pub struct InstructionSet {
    /// `A64`, `A32` or `T32`.
    pub name: String,
    /// Condition on the whole set.
    pub condition: Expr,
    /// The set's encoding set (every bit a free field in A64).
    pub encoding: Encodeset,
    /// Top-level groups.
    pub children: Vec<Node>,
}

/// A child of an instruction set or group.
#[derive(Debug, Clone)]
pub enum Node {
    /// A group (`Instruction.InstructionGroup`).
    Group(Group),
    /// An encoding (`Instruction.Instruction`).
    Instruction(Instruction),
}

/// A group of encodings (`Instruction.InstructionGroup`).
///
/// Group names are not unique; the path from the root is.
#[derive(Debug, Clone)]
pub struct Group {
    /// Name, e.g. `addsub_imm`.
    pub name: String,
    /// Title, often empty.
    pub title: Option<String>,
    /// Condition every encoding in the group also needs: feature checks and,
    /// for a few groups, field tests.
    pub condition: Expr,
    /// The bits common to the group.
    pub encoding: Encodeset,
    /// Subgroups and encodings.
    pub children: Vec<Node>,
}

/// One encoding of an instruction (`Instruction.Instruction`), e.g.
/// `ADD_32_addsub_imm`.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Name, unique within the instruction set.
    pub name: String,
    /// Operation shared by related encodings, e.g. `ADD_addsub_imm`.
    pub operation_id: String,
    /// Feature checks and field tests the word must also satisfy.
    pub condition: Expr,
    /// All 32 bits: fixed bits and named fields.
    pub encoding: Encodeset,
    /// Assembly template: the mnemonic as the first literal, then rule
    /// references.
    pub assembly: Vec<Symbol>,
    /// Which fields each assembly symbol (e.g. `<Xd>`) is encoded in
    /// (`_meta.encoded_in`).
    pub encoded_in: BTreeMap<String, Vec<String>>,
    /// Aliases of this encoding.
    pub aliases: Vec<Alias>,
}

/// An alias of an encoding (`Instruction.InstructionAlias`), e.g. `MOV`
/// for `ADD_32_addsub_imm`.
#[derive(Debug, Clone)]
pub struct Alias {
    /// Name, e.g. `MOV_ADD_32_addsub_imm`.
    pub name: String,
    /// Operation, if the alias has its own.
    pub operation_id: Option<String>,
    /// When the alias applies.
    pub condition: Expr,
    /// When the alias is the preferred disassembly (`false`: never).
    pub preferred: Expr,
    /// Assembly template.
    pub assembly: Vec<Symbol>,
    /// Which fields each assembly symbol is encoded in.
    pub encoded_in: BTreeMap<String, Vec<String>>,
}

/// The bit layout of an instruction word (`Instruction.Encodeset.Encodeset`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encodeset {
    /// Width in bits (32 for A64).
    pub width: u32,
    /// Fixed bits and fields, in the order given.
    pub fields: Vec<EncodeField>,
}

/// Fixed bits (`Instruction.Encodeset.Bits`, no name) or a named field
/// (`Instruction.Encodeset.Field`) of an encoding set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeField {
    /// The field's name; `None` for unnamed fixed bits.
    pub name: Option<String>,
    /// Lowest bit.
    pub start: u32,
    /// Number of bits.
    pub width: u32,
    /// The value: fixed bits as `0`/`1`, free bits as `x`.
    pub value: Pattern,
    /// Bits that *should* have the value given but may differ (`1` marks
    /// such a bit): the hardware ignores them or treats them as CONSTRAINED
    /// UNPREDICTABLE, so a decoder must not require them.
    pub should_be_mask: Pattern,
}

/// A symbol of an assembly template (`Instruction.Symbols.*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Symbol {
    /// Literal text, e.g. the mnemonic.
    Literal(String),
    /// A reference to an [`AssemblyRule`] by id.
    Rule(String),
}

/// An entry of `assembly_rules`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "RawRule")]
pub enum AssemblyRule {
    /// Lexical token (`Instruction.Rules.Token`), e.g. `COMMA`.
    Token {
        /// Regular expression the token matches when parsing.
        pattern: String,
        /// Text written when printing, if the token has a fixed one.
        default: Option<String>,
    },
    /// Sequence of symbols (`Instruction.Rules.Rule`).
    Rule {
        /// The symbol shown in syntax descriptions, e.g. `<imm>`.
        display: Option<String>,
        /// When the rule applies.
        condition: Expr,
        /// The symbols.
        symbols: Vec<Symbol>,
    },
    /// Alternatives (`Instruction.Rules.Choice`); when parsing, the first
    /// that matches wins.
    Choice {
        /// The symbol shown in syntax descriptions, e.g. `<T>`.
        display: Option<String>,
        /// The alternatives; an empty one matches nothing.
        choices: Vec<Vec<Symbol>>,
    },
}

/// Every node in the JSON tree has this shape; which fields are present
/// depends on `_type`. Deserialising one struct instead of a tagged enum
/// avoids serde buffering whole subtrees.
#[derive(Deserialize)]
struct RawNode {
    #[serde(rename = "_type")]
    kind: String,
    name: String,
    #[serde(default)]
    title: Option<String>,
    condition: Expr,
    #[serde(default)]
    preferred: Option<Expr>,
    #[serde(default)]
    encoding: Option<RawEncodeset>,
    #[serde(default)]
    children: Option<Vec<RawNode>>,
    #[serde(default)]
    operation_id: Option<String>,
    #[serde(default)]
    assembly: Option<RawAssembly>,
    #[serde(default, rename = "_meta")]
    meta: Option<RawMeta>,
}

#[derive(Deserialize)]
struct RawEncodeset {
    width: u32,
    values: Vec<RawEncodeField>,
}

#[derive(Deserialize)]
struct RawEncodeField {
    #[serde(rename = "_type")]
    kind: String,
    #[serde(default)]
    name: Option<String>,
    range: Range,
    value: RawValue,
    should_be_mask: RawValue,
}

#[derive(Deserialize)]
struct RawValue {
    value: Pattern,
}

/// A bit range: `width` bits starting at `start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Range {
    /// Lowest bit.
    pub start: u32,
    /// Number of bits.
    pub width: u32,
}

#[derive(Deserialize)]
struct RawAssembly {
    #[serde(default)]
    symbols: Option<Vec<RawSymbol>>,
}

#[derive(Deserialize)]
#[serde(tag = "_type")]
enum RawSymbol {
    #[serde(rename = "Instruction.Symbols.Literal")]
    Literal { value: String },
    #[serde(rename = "Instruction.Symbols.RuleReference")]
    Rule { rule_id: String },
}

#[derive(Deserialize)]
struct RawMeta {
    #[serde(default)]
    encoded_in: BTreeMap<String, Vec<RawIdentifier>>,
}

#[derive(Deserialize)]
struct RawIdentifier {
    value: String,
}

#[derive(Deserialize)]
#[serde(tag = "_type")]
enum RawRule {
    #[serde(rename = "Instruction.Rules.Token")]
    Token {
        pattern: String,
        default: Option<String>,
    },
    #[serde(rename = "Instruction.Rules.Rule")]
    Rule {
        display: Option<String>,
        condition: Expr,
        symbols: Option<RawAssembly>,
    },
    #[serde(rename = "Instruction.Rules.Choice")]
    Choice {
        display: Option<String>,
        choices: Vec<Option<RawAssembly>>,
    },
}

impl From<RawRule> for AssemblyRule {
    fn from(raw: RawRule) -> Self {
        match raw {
            RawRule::Token { pattern, default } => Self::Token { pattern, default },
            RawRule::Rule {
                display,
                condition,
                symbols,
            } => Self::Rule {
                display,
                condition,
                symbols: symbols.map(RawAssembly::symbols).unwrap_or_default(),
            },
            RawRule::Choice { display, choices } => Self::Choice {
                display,
                choices: choices
                    .into_iter()
                    .map(|choice| choice.map(RawAssembly::symbols).unwrap_or_default())
                    .collect(),
            },
        }
    }
}

impl RawAssembly {
    fn symbols(self) -> Vec<Symbol> {
        self.symbols
            .unwrap_or_default()
            .into_iter()
            .map(|symbol| match symbol {
                RawSymbol::Literal { value } => Symbol::Literal(value),
                RawSymbol::Rule { rule_id } => Symbol::Rule(rule_id),
            })
            .collect()
    }
}

impl RawMeta {
    fn encoded_in(meta: Option<Self>) -> BTreeMap<String, Vec<String>> {
        meta.map(|meta| {
            meta.encoded_in
                .into_iter()
                .map(|(symbol, fields)| (symbol, fields.into_iter().map(|f| f.value).collect()))
                .collect()
        })
        .unwrap_or_default()
    }
}

impl TryFrom<RawEncodeset> for Encodeset {
    type Error = String;

    fn try_from(raw: RawEncodeset) -> Result<Self, String> {
        let fields = raw
            .values
            .into_iter()
            .map(|field| {
                let name = match field.kind.as_str() {
                    "Instruction.Encodeset.Bits" => None,
                    "Instruction.Encodeset.Field" => {
                        Some(field.name.ok_or("an encoding field has no name")?)
                    }
                    other => return Err(format!("unknown encoding set entry `{other}`")),
                };
                let range = field.range;
                if field.value.value.width() != range.width
                    || field.should_be_mask.value.width() != range.width
                    || range.start + range.width > raw.width
                {
                    return Err(format!(
                        "encoding field {name:?} at {}+{} has value {} and should-be mask {}",
                        range.start, range.width, field.value.value, field.should_be_mask.value
                    ));
                }
                Ok(EncodeField {
                    name,
                    start: range.start,
                    width: range.width,
                    value: field.value.value,
                    should_be_mask: field.should_be_mask.value,
                })
            })
            .collect::<Result<_, String>>()?;
        Ok(Self {
            width: raw.width,
            fields,
        })
    }
}

impl RawNode {
    fn encodeset(&mut self) -> Result<Encodeset, String> {
        let encoding = self
            .encoding
            .take()
            .ok_or_else(|| format!("{} has no encoding", self.name))?;
        Encodeset::try_from(encoding).map_err(|error| format!("{}: {error}", self.name))
    }

    /// The instruction set this node describes.
    fn into_instruction_set(mut self) -> Result<InstructionSet, String> {
        if self.kind != "Instruction.InstructionSet" {
            return Err(format!(
                "{} is a {}, not an instruction set",
                self.name, self.kind
            ));
        }
        Ok(InstructionSet {
            encoding: self.encodeset()?,
            children: self.take_children()?,
            name: self.name,
            condition: self.condition,
        })
    }

    /// The children, converted; they are moved out of `self`.
    fn take_children(&mut self) -> Result<Vec<Node>, String> {
        self.children
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(Self::into_node)
            .collect()
    }

    fn into_node(mut self) -> Result<Node, String> {
        match self.kind.as_str() {
            "Instruction.InstructionGroup" => Ok(Node::Group(Group {
                encoding: self.encodeset()?,
                children: self.take_children()?,
                name: self.name,
                title: self.title.filter(|title| !title.is_empty()),
                condition: self.condition,
            })),
            "Instruction.Instruction" => {
                let aliases = self
                    .children
                    .take()
                    .unwrap_or_default()
                    .into_iter()
                    .map(Self::into_alias)
                    .collect::<Result<_, _>>()?;
                Ok(Node::Instruction(Instruction {
                    encoding: self.encodeset()?,
                    operation_id: self
                        .operation_id
                        .ok_or_else(|| format!("{} has no operation_id", self.name))?,
                    assembly: self.assembly.map(RawAssembly::symbols).unwrap_or_default(),
                    encoded_in: RawMeta::encoded_in(self.meta),
                    aliases,
                    name: self.name,
                    condition: self.condition,
                }))
            }
            other => Err(format!("{}: unexpected node type `{other}`", self.name)),
        }
    }

    fn into_alias(self) -> Result<Alias, String> {
        if self.kind != "Instruction.InstructionAlias" {
            return Err(format!(
                "{}: an encoding has a child of type `{}`",
                self.name, self.kind
            ));
        }
        Ok(Alias {
            preferred: self
                .preferred
                .ok_or_else(|| format!("alias {} has no `preferred`", self.name))?,
            assembly: self.assembly.map(RawAssembly::symbols).unwrap_or_default(),
            encoded_in: RawMeta::encoded_in(self.meta),
            name: self.name,
            operation_id: self.operation_id,
            condition: self.condition,
        })
    }
}

impl InstructionSet {
    /// Every encoding with the groups above it, outermost first, in tree
    /// order.
    pub fn encodings(&self) -> Vec<(Vec<&Group>, &Instruction)> {
        fn visit<'a>(
            nodes: &'a [Node],
            path: &mut Vec<&'a Group>,
            out: &mut Vec<(Vec<&'a Group>, &'a Instruction)>,
        ) {
            for node in nodes {
                match node {
                    Node::Group(group) => {
                        path.push(group);
                        visit(&group.children, path, out);
                        path.pop();
                    }
                    Node::Instruction(instruction) => out.push((path.clone(), instruction)),
                }
            }
        }
        let mut out = Vec::new();
        visit(&self.children, &mut Vec::new(), &mut out);
        out
    }
}

impl Instruction {
    /// The mnemonic: the template's first literal, e.g. `ADD`.
    pub fn mnemonic(&self) -> Option<&str> {
        self.assembly.iter().find_map(|symbol| match symbol {
            Symbol::Literal(text) => Some(text.as_str()),
            Symbol::Rule(_) => None,
        })
    }
}
