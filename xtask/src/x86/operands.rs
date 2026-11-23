//! Instruction operands (`generated/operand.rs`): the operand list XED
//! reports for each instruction, and the operand width codes.
//!
//! XED builds an instruction's operands from its `OPERANDS` field in this
//! order (`generator.py`):
//!
//! 1. the operands as written, a state macro standing for its expansion
//!    (forced suppressed);
//! 2. for the first `STACKPUSH`/`STACKPOP` register, the stack memory
//!    operand `MEMi`, `BASEi=SrSP()` and `SEGi=FINAL_SSEGi()` (`i` is 0, or 1
//!    when `MEM0` exists);
//! 3. each capture of the pattern (`REG[rrr]`), as a suppressed operand;
//! 4. `REGn=rFLAGS()` when the instruction affects x86 flags and lists no
//!    flags register, `n` above every `REGm`, its action from the flag
//!    records.
//!
//! Operands of internal fields and error operands are then dropped, and an
//! operand without a visibility takes its field's default. The width code
//! is the operand's own, else the default `all-extra-widths.txt` gives its
//! nonterminal, register or bare name.

use std::collections::{BTreeMap, HashMap};

use binbun_xed::fields::{self, Field, Scope};
use binbun_xed::flags;
use binbun_xed::operands::{Action, Operand, Value, Visibility};
use binbun_xed::pattern::{Pattern, Token};
use binbun_xed::tables::{ElementType, ExtraWidth, ExtraWidthKind, Width};
use binbun_xed::{Datafile, StateMacros, operands};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::forms::Instruction;
use super::output;
use super::state::ident_for;
use crate::Result;
use crate::codegen::{GeneratedFile, XED_NOTICE, count, lit};
use crate::naming::{camel_case, ident};

/// One operand as XED reports it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Template {
    name: String,
    visibility: &'static str,
    action: &'static str,
    width: String,
    /// Element type (XED's xtype), lower case.
    xtype: String,
    /// Print decorations: conversion-table names (`ZEROSTR`), or
    /// `MULTIREGn`.
    conversions: Vec<String>,
    /// The AVX-512 write mask (`REG0`/`REG1` looked up by `MASK1()`).
    writemask: bool,
}

/// Where each instruction's operands are in the generated sequence table.
#[derive(Debug)]
pub struct OperandLists {
    /// Per instruction: first index into the sequence table, and count.
    pub slices: Vec<(u16, u8)>,
}

/// One table of `all-conversion-table.txt`: the texts a decoder field
/// selects, e.g. `ZEROSTR(XED_OPERAND_ZEROING)` with `0 -> ''`,
/// `1 -> '{z}'`.
#[derive(Debug)]
pub struct ConversionTable {
    pub name: String,
    /// The field (without `XED_OPERAND_`).
    pub field: String,
    /// The texts in the order written. XED indexes them by position, not
    /// by the number written before each (which `DFVSTR` gets wrong).
    pub strings: Vec<String>,
}

/// Parses `all-conversion-table.txt`.
pub fn conversion_tables(file: &Datafile<'_>) -> Result<Vec<ConversionTable>> {
    let mut tables: Vec<ConversionTable> = Vec::new();
    for line in file.lines() {
        let text = line.text().trim();
        if let Some(header) = text.strip_suffix("::") {
            let (name, field) = header
                .strip_suffix(')')
                .and_then(|h| h.split_once('('))
                .ok_or_else(|| format!("line {}: bad conversion header", line.number))?;
            let field = field
                .strip_prefix("XED_OPERAND_")
                .ok_or_else(|| format!("line {}: bad conversion field", line.number))?;
            tables.push(ConversionTable {
                name: name.to_owned(),
                field: field.to_owned(),
                strings: Vec::new(),
            });
        } else if let Some((_, string)) = text.split_once("->") {
            let string = string
                .trim()
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .ok_or_else(|| format!("line {}: bad conversion text", line.number))?;
            tables
                .last_mut()
                .ok_or_else(|| format!("line {}: text before a table", line.number))?
                .strings
                .push(string.to_owned());
        } else {
            return Err(format!("line {}: unexpected `{text}`", line.number).into());
        }
    }
    Ok(tables)
}

#[expect(
    clippy::too_many_arguments,
    reason = "one argument per parsed datafile or earlier generator result"
)]
pub fn generate(
    instructions: &[Instruction<'_>],
    added: &[Vec<Added>],
    fields: &[Field<'_>],
    macros: &StateMacros<'_>,
    widths: &[Width<'_>],
    extra_widths: &[ExtraWidth<'_>],
    element_types: &[ElementType<'_>],
    conversions: &[ConversionTable],
) -> Result<(GeneratedFile, OperandLists)> {
    let fields: HashMap<&str, &Field<'_>> = fields.iter().map(|f| (f.name, f)).collect();
    let defaults: HashMap<(ExtraWidthKind, &str), &str> = extra_widths
        .iter()
        .map(|e| ((e.kind, e.name), e.width))
        .collect();
    // Width code → its default element type (the last definition wins).
    let known_widths: HashMap<String, &str> = widths
        .iter()
        .map(|w| (w.name.to_ascii_uppercase(), w.element_type))
        .collect();

    let mut templates: Vec<Template> = Vec::new();
    let mut template_index: HashMap<Template, u16> = HashMap::new();
    let mut sequences: Vec<u16> = Vec::new();
    let mut sequence_index: HashMap<Vec<u16>, u16> = HashMap::new();
    let mut slices = Vec::with_capacity(instructions.len());
    for (instruction, added) in instructions.iter().zip(added) {
        let list = operand_list(
            instruction,
            added,
            &fields,
            macros,
            &defaults,
            &known_widths,
        )?;
        let mut ids = Vec::with_capacity(list.len());
        for template in list {
            if template.width != "INVALID" && !known_widths.contains_key(&template.width) {
                return Err(format!(
                    "line {}: unknown width {}",
                    instruction.line, template.width
                )
                .into());
            }
            if !element_types.iter().any(|e| e.name == template.xtype) {
                return Err(format!(
                    "line {}: unknown element type {}",
                    instruction.line, template.xtype
                )
                .into());
            }
            for conversion in &template.conversions {
                if !conversion.starts_with("MULTIREG")
                    && !conversions.iter().any(|c| c.name == *conversion)
                {
                    return Err(format!(
                        "line {}: unknown conversion {conversion}",
                        instruction.line
                    )
                    .into());
                }
            }
            let id = if let Some(&id) = template_index.get(&template) {
                id
            } else {
                let id = u16::try_from(templates.len())?;
                templates.push(template.clone());
                template_index.insert(template, id);
                id
            };
            ids.push(id);
        }
        let count = u8::try_from(ids.len())?;
        let start = if let Some(&start) = sequence_index.get(&ids) {
            start
        } else {
            let start = u16::try_from(sequences.len())?;
            sequences.extend_from_slice(&ids);
            sequence_index.insert(ids, start);
            start
        };
        slices.push((start, count));
    }

    let tokens = emit(
        &templates,
        &sequences,
        widths,
        element_types,
        conversions,
        &fields,
    )?;
    let file = GeneratedFile {
        path: output("operand"),
        notice: XED_NOTICE,
        docs: vec!["Operand names, width codes and each instruction's operand list.".to_owned()],
        tokens,
    };
    Ok((file, OperandLists { slices }))
}

/// An operand XED adds to those an instruction lists.
#[derive(Debug, Clone)]
pub struct Added {
    /// As an operand word, e.g. `BASE0=SrSP():rw:SUPP`.
    pub word: String,
    /// A pattern capture: reported, but its value comes from the pattern,
    /// not from decoding the operand.
    pub capture: bool,
}

/// The operands XED adds to those `instruction` lists (steps 2 to 4 of
/// the module documentation).
pub fn added(instruction: &Instruction<'_>, fields: &[Field<'_>]) -> Result<Vec<Added>> {
    let line = instruction.line;
    let written = &instruction.operands;
    let mut extra: Vec<Added> = Vec::new();
    let mut push = |word: String, capture: bool| extra.push(Added { word, capture });
    // 2. The stack operand.
    let stack = written.iter().find_map(|op| {
        if let Value::Register(r @ ("XED_REG_STACKPUSH" | "XED_REG_STACKPOP")) = op.value {
            Some((r, op.width))
        } else {
            None
        }
    });
    if let Some((register, width)) = stack {
        let (memory, _) = indices(written.iter().map(|op| op.name));
        let width = width.ok_or_else(|| format!("line {line}: stack operand without a width"))?;
        let action = if register == "XED_REG_STACKPUSH" {
            "w"
        } else {
            "r"
        };
        push(format!("MEM{memory}:{action}:{width}:SUPP"), false);
        push(format!("BASE{memory}=SrSP():rw:SUPP"), false);
        push(format!("SEG{memory}=FINAL_SSEG{memory}():r:SUPP"), false);
    }
    // 3. Pattern captures.
    if let Pattern::Tokens(tokens) = &instruction.pattern {
        for token in tokens {
            if let Token::Capture { field, .. } = token {
                let width = fields
                    .iter()
                    .find(|f| f.name == *field)
                    .ok_or_else(|| format!("line {line}: capture of unknown field {field}"))?
                    .width;
                // The value is what the pattern captures; 0 stands for it.
                push(format!("{field}=0:r:i{width}:SUPP"), true);
            }
        }
    }
    // 4. The flags register.
    if let Some(action) = flags_action(instruction)?
        && !written.iter().any(names_flags)
    {
        let added = extra
            .iter()
            .map(|added| added.word.split(['=', ':']).next().unwrap_or_default());
        let (_, register) = indices(written.iter().map(|op| op.name).chain(added));
        extra.push(Added {
            word: format!("REG{register}=rFLAGS():{action}:SUPP"),
            capture: false,
        });
    }
    Ok(extra)
}

/// Parses the words of `added` operands.
pub fn parse_added<'w>(
    line: u32,
    added: impl IntoIterator<Item = &'w Added>,
    macros: &StateMacros<'w>,
) -> Result<Vec<Operand<'w>>> {
    let mut out = Vec::new();
    for added in added {
        for parsed in operands::parse(line, &added.word, macros)? {
            if let operands::Word::Operand(operand) = parsed {
                out.push(operand);
            }
        }
    }
    Ok(out)
}

/// One operand XED reports for an instruction, with its visibility
/// (`Explicit`, `Implicit` or `Suppressed`).
#[derive(Debug)]
pub struct Reported<'a> {
    pub operand: Operand<'a>,
    pub visibility: &'static str,
}

/// The operands XED reports for `instruction`, in order (the order of
/// `Instruction::operands` at run time): those written, then those XED
/// adds; macro expansions are suppressed; internal fields and encoder
/// conditions are not reported.
pub fn reported<'a>(
    instruction: &Instruction<'a>,
    added: &'a [Added],
    fields: &HashMap<&str, &Field<'_>>,
    macros: &StateMacros<'a>,
) -> Result<Vec<Reported<'a>>> {
    let line = instruction.line;
    let mut list: Vec<(Operand<'a>, bool)> = Vec::new();
    for word in instruction.operand_text.split_whitespace() {
        let expanded = macros.get(word).is_some();
        for parsed in operands::parse(line, word, macros)? {
            if let operands::Word::Operand(operand) = parsed {
                list.push((operand, expanded));
            }
        }
    }
    list.extend(
        parse_added(line, added, macros)?
            .into_iter()
            .map(|op| (op, false)),
    );
    let mut out = Vec::new();
    for (operand, expanded) in list {
        if matches!(operand.value, Value::Error(_)) {
            continue;
        }
        let field = fields
            .get(operand.name)
            .ok_or_else(|| format!("line {line}: operand of unknown field {}", operand.name))?;
        if field.scope == Scope::Internal {
            continue;
        }
        let visibility = if expanded {
            "Suppressed"
        } else {
            match operand.visibility {
                Some(Visibility::Explicit) => "Explicit",
                Some(Visibility::Implicit) => "Implicit",
                Some(Visibility::Suppressed) => "Suppressed",
                Some(Visibility::EncoderCondition) => continue,
                None => match field.visibility {
                    fields::Visibility::Explicit => "Explicit",
                    fields::Visibility::Suppressed => "Suppressed",
                },
            }
        };
        out.push(Reported {
            operand,
            visibility,
        });
    }
    Ok(out)
}

/// The operands XED reports for `instruction`, in order, as templates.
fn operand_list(
    instruction: &Instruction<'_>,
    added: &[Added],
    fields: &HashMap<&str, &Field<'_>>,
    macros: &StateMacros<'_>,
    defaults: &HashMap<(ExtraWidthKind, &str), &str>,
    default_xtypes: &HashMap<String, &str>,
) -> Result<Vec<Template>> {
    let mut out = Vec::new();
    for Reported {
        operand,
        visibility,
    } in reported(instruction, added, fields, macros)?
    {
        let width = if let Some(width) = operand.width {
            width.to_ascii_uppercase()
        } else {
            let key = match operand.value {
                Value::Lookup(nt) => Some((ExtraWidthKind::Nt, nt)),
                Value::Register(register) => {
                    Some((ExtraWidthKind::Reg, register.trim_start_matches("XED_REG_")))
                }
                Value::Present => Some((ExtraWidthKind::ImmConst, operand.name)),
                Value::Error(_) | Value::Enumerator(_) | Value::Number(_) | Value::Bits(_) => None,
            };
            key.and_then(|key| defaults.get(&key))
                .map_or_else(|| "INVALID".to_owned(), |w| w.to_ascii_uppercase())
        };
        // XED's xtype: the operand's own, else its width's default, else
        // `int`.
        let xtype = operand
            .element_type
            .map(str::to_owned)
            .or_else(|| {
                (width != "INVALID")
                    .then(|| default_xtypes.get(&width).map(|x| x.to_ascii_lowercase()))
                    .flatten()
            })
            .unwrap_or_else(|| "int".to_owned());
        let mut conversions: Vec<String> =
            operand.conversions.iter().map(|&c| c.to_owned()).collect();
        if let Some((_, count)) = operand.multireg
            && count >= 2
        {
            conversions.push(format!("MULTIREG{count}"));
        }
        out.push(Template {
            name: operand.name.to_owned(),
            visibility,
            action: action_name(operand.action),
            width,
            xtype,
            conversions,
            writemask: matches!(operand.name, "REG0" | "REG1")
                && operand.value == Value::Lookup("MASK1"),
        });
    }
    Ok(out)
}

/// The memory operand index and the register operand index after `names`
/// (XED's `find_max_memidx_and_regidx`).
fn indices<'n>(names: impl Iterator<Item = &'n str>) -> (u32, u32) {
    let (mut memory, mut register) = (0, 0);
    for name in names {
        match name {
            "MEM0" => memory = 1,
            "MEM1" => memory = 2,
            _ => {}
        }
        if let Some(n) = name.strip_prefix("REG").and_then(|n| n.parse::<u32>().ok()) {
            register = register.max(n + 1);
        }
    }
    (memory, register)
}

/// Whether `operand` is a flags register (XED's `skip_flags_reg_gen`).
fn names_flags(operand: &Operand<'_>) -> bool {
    matches!(
        operand.value,
        Value::Register("XED_REG_FLAGS" | "XED_REG_EFLAGS" | "XED_REG_RFLAGS")
            | Value::Lookup("rFLAGS")
    )
}

/// The action of the `rFLAGS()` operand XED adds, if it adds one: `r`
/// if a record reads flags, `c` if one writes them conditionally or does
/// nothing, `w` if one writes them (XED's `flags_info_t.rw_action`).
fn flags_action(instruction: &Instruction<'_>) -> Result<Option<&'static str>> {
    let Some(text) = instruction.record.flags else {
        return Ok(None);
    };
    let records = flags::parse(instruction.line, text)?;
    let x87 = |flag| {
        matches!(
            flag,
            flags::Flag::Fc0 | flags::Flag::Fc1 | flags::Flag::Fc2 | flags::Flag::Fc3
        )
    };
    if !records
        .iter()
        .any(|r| r.actions.iter().any(|a| !x87(a.flag)))
    {
        return Ok(None);
    }
    let (mut read, mut conditional, mut write) = (false, false, false);
    for record in &records {
        if record.actions.is_empty() {
            conditional = true;
        }
        read |= record.actions.iter().any(|a| a.action.reads());
        let writes = record.actions.iter().any(|a| a.action.writes());
        write |= writes;
        conditional |= writes && record.strength == flags::Strength::May;
    }
    Ok(Some(match (read, conditional, write) {
        (true, false, false) => "r",
        (false, false, true) => "w",
        (true, false, true) => "rw",
        (false, true, true) => "cw",
        (true, true, true) => "rcw",
        other => return Err(format!("line {}: flags action {other:?}", instruction.line).into()),
    }))
}

/// The `ElementType` variant of an xtype: `f32` → `F32`, a leading count
/// moved to the end (`2f16` → `F16x2`).
fn xtype_ident(name: &str) -> Result<proc_macro2::Ident> {
    let digits = name.len() - name.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    let (count, rest) = name.split_at(digits);
    if count.is_empty() {
        ident(&camel_case(rest))
    } else {
        ident(&format!("{}x{count}", camel_case(rest)))
    }
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::Read => "Read",
        Action::Write => "Write",
        Action::ReadWrite => "ReadWrite",
        Action::ConditionalRead => "ConditionalRead",
        Action::ConditionalWrite => "ConditionalWrite",
        Action::ConditionalReadWrite => "ConditionalReadWrite",
        Action::ReadConditionalWrite => "ReadConditionalWrite",
    }
}

fn emit(
    templates: &[Template],
    sequences: &[u16],
    widths: &[Width<'_>],
    element_types: &[ElementType<'_>],
    conversions: &[ConversionTable],
    fields: &HashMap<&str, &Field<'_>>,
) -> Result<TokenStream> {
    let names: BTreeMap<&str, usize> = {
        let mut sorted: Vec<&str> = templates.iter().map(|t| t.name.as_str()).collect();
        sorted.sort_unstable();
        sorted.dedup();
        sorted
            .into_iter()
            .enumerate()
            .map(|(i, n)| (n, i))
            .collect()
    };
    let name_variants = names
        .keys()
        .map(|n| ident(&camel_case(n)))
        .collect::<Result<Vec<_>>>()?;
    let name_strings: Vec<&str> = names.keys().copied().collect();
    let name_count = count(names.len());

    // A width code defined twice (`i8`) keeps its first place and its last
    // definition, as XED's dictionary of widths does.
    let mut unique: Vec<(String, [u32; 4])> = Vec::new();
    for width in widths {
        let name = width.name.to_ascii_uppercase();
        match unique.iter_mut().find(|(n, _)| *n == name) {
            Some(entry) => entry.1 = width.bits,
            None => unique.push((name, width.bits)),
        }
    }
    let width_variants = unique
        .iter()
        .map(|(name, _)| ident(&camel_case(name)))
        .collect::<Result<Vec<_>>>()?;
    let width_strings: Vec<&str> = unique.iter().map(|(name, _)| name.as_str()).collect();
    let width_bits = unique
        .iter()
        .map(|(_, bits)| {
            let bits = bits
                .iter()
                .map(|&b| Ok(lit(u16::try_from(b)?)))
                .collect::<Result<Vec<_>>>()?;
            Ok(quote!([#(#bits),*]))
        })
        .collect::<Result<Vec<_>>>()?;
    let width_count = count(unique.len());

    // An element type defined twice (`2bf16`) keeps its first place and its
    // last definition.
    let mut unique_types: Vec<&ElementType<'_>> = Vec::new();
    for element_type in element_types {
        match unique_types
            .iter_mut()
            .find(|e| e.name == element_type.name)
        {
            Some(entry) => *entry = element_type,
            None => unique_types.push(element_type),
        }
    }
    let xtype_variants = unique_types
        .iter()
        .map(|e| xtype_ident(e.name))
        .collect::<Result<Vec<_>>>()?;
    let xtype_strings: Vec<&str> = unique_types.iter().map(|e| e.name).collect();
    let xtype_bases = unique_types
        .iter()
        .map(|e| {
            let base = format_ident!("{}", format!("{:?}", e.base));
            quote!(ElementBase::#base)
        })
        .collect::<Vec<_>>();
    let xtype_bits = unique_types
        .iter()
        .map(|e| Ok(lit(u16::try_from(e.bits)?)))
        .collect::<Result<Vec<_>>>()?;

    let conversion_variants = conversions
        .iter()
        .map(|c| ident(&camel_case(&c.name)))
        .collect::<Result<Vec<_>>>()?;
    let conversion_texts = conversions
        .iter()
        .map(|c| {
            if !fields.contains_key(c.field.as_str()) {
                return Err(format!("conversion {}: unknown field {}", c.name, c.field).into());
            }
            let field = ident_for(&c.field);
            let strings = &c.strings;
            Ok(quote!({
                const TEXTS: &[&str] = &[#(#strings),*];
                TEXTS.get(usize::from(s.#field)).copied().unwrap_or("BADCVT")
            }))
        })
        .collect::<Result<Vec<_>>>()?;

    let entries = templates
        .iter()
        .map(|t| {
            let name = ident(&camel_case(&t.name))?;
            let visibility = format_ident!("{}", t.visibility);
            let action = format_ident!("{}", t.action);
            let width = ident(&camel_case(&t.width))?;
            let xtype = xtype_ident(&t.xtype)?;
            let conversions = t
                .conversions
                .iter()
                .map(|c| {
                    if let Some(count) = c.strip_prefix("MULTIREG") {
                        let count = lit(count.parse::<u8>()?);
                        Ok(quote!(Conversion::Multireg(#count)))
                    } else {
                        let variant = ident(&camel_case(c))?;
                        Ok(quote!(Conversion::#variant))
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            let writemask = t.writemask;
            Ok(quote!(OperandTemplate {
                name: OperandName::#name,
                visibility: Visibility::#visibility,
                action: Action::#action,
                width: OperandWidth::#width,
                element_type: ElementType::#xtype,
                conversions: &[#(#conversions),*],
                writemask: #writemask,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let template_count = count(templates.len());
    let sequence_count = count(sequences.len());
    let sequences = sequences.iter().map(|&s| lit(s));

    Ok(quote! {
        use crate::decode::operand::{Action, ElementBase, OperandTemplate, Visibility};
        use crate::generated::state::Fields;

        /// An operand's name: which decoder field holds its value (XED's
        /// `xed_operand_enum_t`).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u8)]
        pub enum OperandName {
            #(#[doc = #name_strings] #name_variants,)*
        }

        impl OperandName {
            /// Number of names.
            pub const COUNT: usize = #name_count;

            /// XED's name.
            pub const fn as_str(self) -> &'static str {
                match self {
                    #(Self::#name_variants => #name_strings,)*
                }
            }
        }

        /// An operand width code (XED's `xed_operand_width_enum_t`): the
        /// operand's size, often depending on the effective operand size.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u8)]
        pub enum OperandWidth {
            #(#[doc = #width_strings] #width_variants,)*
        }

        impl OperandWidth {
            /// Number of width codes.
            pub const COUNT: usize = #width_count;

            /// XED's name.
            pub const fn as_str(self) -> &'static str {
                match self {
                    #(Self::#width_variants => #width_strings,)*
                }
            }

            /// Width in bits for each effective operand size (8, 16, 32 and
            /// 64 bits, XED's `EOSZ` 0 to 3); 0 when it varies otherwise.
            pub const fn bits(self) -> [u16; 4] {
                WIDTH_BITS[self as usize]
            }
        }

        static WIDTH_BITS: [[u16; 4]; #width_count] = [#(#width_bits),*];

        /// An operand's element type (XED's xtype).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u8)]
        pub enum ElementType {
            #(#[doc = #xtype_strings] #xtype_variants,)*
        }

        impl ElementType {
            /// XED's name.
            pub const fn as_str(self) -> &'static str {
                match self {
                    #(Self::#xtype_variants => #xtype_strings,)*
                }
            }

            /// The kind of element.
            pub const fn base(self) -> ElementBase {
                match self {
                    #(Self::#xtype_variants => #xtype_bases,)*
                }
            }

            /// Bits per element; 0 when the instruction decides.
            pub const fn bits(self) -> u16 {
                match self {
                    #(Self::#xtype_variants => #xtype_bits,)*
                }
            }
        }

        /// A decoration printed after an operand (XED's operand
        /// conversions): text chosen by a decoder field, or the `+n` of an
        /// operand naming several registers.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Conversion {
            #(#conversion_variants,)*
            /// The operand names this many consecutive registers.
            Multireg(u8),
        }

        impl Conversion {
            /// The text for decoded fields `s` (XED's `xed_print_cvt`;
            /// `BADCVT` for a value outside the table).
            pub fn text(self, s: &Fields) -> &'static str {
                match self {
                    #(Self::#conversion_variants => #conversion_texts,)*
                    Self::Multireg(_) => "",
                }
            }
        }

        /// Every distinct operand.
        pub static TEMPLATES: [OperandTemplate; #template_count] = [#(#entries),*];

        /// Instructions' operand lists, as indices into [`TEMPLATES`].
        pub static SEQUENCES: [u16; #sequence_count] = [#(#sequences),*];

        /// The template a [`SEQUENCES`] entry names.
        #[inline]
        pub fn template(index: u16) -> &'static OperandTemplate {
            &TEMPLATES[usize::from(index)]
        }
    })
}
