//! Operand semantics: how the assembly symbols of an encoding or alias
//! become operands, written by hand, one file per slice of the instruction
//! set.
//!
//! An AARCHMRS assembly template is a mnemonic followed by symbols
//! (`'ADD' SPACE WdWSP_option COMMA WnWSP_option COMMA hash imm__17
//! optional_shift`). The generator cuts it at the top-level commas into
//! *slots* and writes each slot as Arm writes the syntax, its *key*:
//! `<Wd|WSP>`, `<Wn|WSP>`, `#<imm>`, `{, <shift>}`. A [`Symbol`] says what a
//! key means: given the slot (its fields, the form's other fields), it
//! returns the code that pushes the slot's operands. Keys can be narrowed to
//! the fields they are encoded in and to particular forms, and the most
//! specific entry wins.
//!
//! Every form must be covered: generation fails, listing every key without
//! an entry, if a form uses a slot no entry matches.

mod integer;
mod ldst;
mod simd;
mod sme;
mod sve;
mod system;
mod vector;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use xtask::aarchmrs::{AssemblyRule, Instruction, Pattern, Symbol as Piece};

use super::cond;
use super::reserved::value_named;
use crate::Result;
use crate::codegen::lit;

/// Every slice's symbols, with the group path prefixes they apply to
/// (none: every group). Slices name the same syntax differently (`<V><d>`
/// of SVE reductions and of `AdvSIMD` scalars), so a slice's entries stay in
/// its groups; the integer entries (general registers, plain immediates)
/// are everyone's.
const TABLES: &[(&[&str], &[Symbol])] = &[
    (&[], integer::SYMBOLS),
    (&["ldst"], ldst::SYMBOLS),
    (&["simd_dp"], simd::SYMBOLS),
    (
        &[
            "control/systeminstrs",
            "control/systeminstrswithreg",
            "control/systemmove",
            "control/systemmovepr",
            "control/syspairinstrs",
            "control/pstate",
        ],
        system::SYMBOLS,
    ),
    (&["sve"], sve::SYMBOLS),
    (&["sve", "sme"], vector::SYMBOLS),
    (&["sme"], sme::SYMBOLS),
];

/// Whether the group path `path` is `prefix` or below it.
fn under(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// What a [`Symbol`] produces.
#[derive(Clone, Copy)]
pub enum Build {
    /// Code pushing operands onto `ops: &mut Operands`, given `word: u32`.
    Operands(fn(&Slot<'_>) -> Result<TokenStream>),
    /// Text by the value of the slot's fields (mnemonic suffixes such as
    /// `b.<cond>`); index `i` is the text for value `i`.
    Text(&'static [&'static str]),
}

/// The meaning of a slot key.
#[derive(Clone, Copy)]
pub struct Symbol {
    /// The key, as Arm writes the syntax: `<Xn|SP>`, `#<imm>`,
    /// `{, <shift> #<amount>}`.
    pub key: &'static str,
    /// The fields the slot is encoded in, in order; empty for any.
    pub fields: &'static [&'static str],
    /// The forms (encoding names, or `ENCODING__ALIAS` for aliases) it is
    /// limited to; empty for any.
    pub forms: &'static [&'static str],
    /// What it produces.
    pub build: Build,
}

impl Symbol {
    /// How specific the entry is: forms count more than fields.
    fn rank(&self) -> u8 {
        u8::from(!self.forms.is_empty()) * 2 + u8::from(!self.fields.is_empty())
    }
}

/// One slot of a template, with what entries need to generate its code.
pub struct Slot<'a> {
    /// The key.
    pub key: String,
    /// The form's name (`ENCODING` or `ENCODING__ALIAS`).
    pub form: &'a str,
    /// The encoding's group path (`sve/sve_maskimm`).
    pub path: &'a str,
    /// The encoding.
    pub instruction: &'a Instruction,
    /// The fields the slot's symbols are encoded in, in order.
    pub fields: Vec<String>,
    /// Text of value-named alternatives of the slot's choices, by display:
    /// pattern per field, then the alternative's text (lower case).
    pub names: BTreeMap<String, Vec<(Vec<Pattern>, String)>>,
    /// The form's `encoded_in`.
    encoded_in: &'a BTreeMap<String, Vec<String>>,
}

impl Slot<'_> {
    /// `(word >> start) & mask` for the encoding's field `name`, a `u32`.
    pub fn field(&self, name: &str) -> Result<TokenStream> {
        let (start, width) = cond::field(&self.instruction.encoding, name)
            .ok_or_else(|| format!("{}: no field {name}", self.form))?;
        Ok(extract(start, width))
    }

    /// Width of the encoding's field `name`.
    pub fn width(&self, name: &str) -> Result<u32> {
        cond::field(&self.instruction.encoding, name)
            .map(|(_, width)| width)
            .ok_or_else(|| format!("{}: no field {name}", self.form).into())
    }

    /// The fields a display (`<imm>`) is encoded in, concatenated (first
    /// field most significant): the expression and its width.
    pub fn display(&self, display: &str) -> Result<(TokenStream, u32)> {
        let fields = self
            .encoded_in
            .get(display)
            .ok_or_else(|| format!("{}: {display} is not encoded", self.form))?;
        let mut value = quote! { 0u32 };
        let mut total = 0;
        for name in fields {
            let width = self.width(name)?;
            let field = self.field(name)?;
            let shift = lit(width);
            value = if total == 0 {
                field
            } else {
                quote! { ((#value) << #shift) | #field }
            };
            total += width;
        }
        Ok((value, total))
    }

    /// The slot's fields concatenated, as [`Slot::display`] does for one
    /// display.
    pub fn value(&self) -> Result<(TokenStream, u32)> {
        let mut value = quote! { 0u32 };
        let mut total = 0;
        for name in &self.fields {
            let width = self.width(name)?;
            let field = self.field(name)?;
            let shift = lit(width);
            value = if total == 0 {
                field
            } else {
                quote! { ((#value) << #shift) | #field }
            };
            total += width;
        }
        Ok((value, total))
    }

    /// A `match` on the fields of `display` choosing between the texts of
    /// its value-named alternatives; `wrap` turns a text into the arm's
    /// expression, and values without an alternative take `otherwise`.
    pub fn match_names(
        &self,
        display: &str,
        wrap: impl Fn(&str) -> TokenStream,
        otherwise: &TokenStream,
    ) -> Result<TokenStream> {
        let names = self
            .names
            .get(display)
            .ok_or_else(|| format!("{}: {display} has no value-named alternatives", self.form))?;
        let fields = self
            .encoded_in
            .get(display)
            .ok_or_else(|| format!("{}: {display} is not encoded", self.form))?;
        let (value, _) = self.display(display)?;
        let mut arms = Vec::new();
        let mut seen = BTreeSet::new();
        for (patterns, text) in names {
            // Concatenate the per-field patterns into one mask/value.
            let mut mask = 0u32;
            let mut bits = 0u32;
            for (pattern, name) in patterns.iter().zip(fields) {
                let width = self.width(name)?;
                mask = (mask << width) | u32::try_from(pattern.mask())?;
                bits = (bits << width) | u32::try_from(pattern.value())?;
            }
            if !seen.insert((mask, bits)) {
                continue;
            }
            let body = wrap(text);
            let (mask, bits) = (lit(mask), lit(bits));
            arms.push(quote! { v if v & #mask == #bits => #body, });
        }
        Ok(quote! {
            match #value {
                #(#arms)*
                _ => #otherwise,
            }
        })
    }
}

/// `(word >> start) & mask` without a shift by 0.
pub fn extract(start: u32, width: u32) -> TokenStream {
    let mask = lit((1u64 << width) - 1);
    if start == 0 {
        return quote! { (word & #mask) };
    }
    let start = lit(start);
    quote! { ((word >> #start) & #mask) }
}

/// Code pushing `operand` onto `ops`.
pub fn push(operand: &TokenStream) -> TokenStream {
    quote! { ops.push(#operand); }
}

/// A register of `class` (a `RegisterClass` variant) numbered `number`.
pub fn register(class: &str, number: &TokenStream) -> TokenStream {
    let class = format_ident!("{class}");
    quote! { Operand::Register(Register::new(RegisterClass::#class, (#number) as u8)) }
}

/// An unsigned immediate written in hex.
pub fn unsigned(value: &TokenStream) -> TokenStream {
    quote! { Operand::Immediate(Immediate::unsigned((#value) as u64)) }
}

/// An unsigned immediate written in decimal.
pub fn decimal(value: &TokenStream) -> TokenStream {
    quote! { Operand::Immediate(Immediate::unsigned((#value) as u64).decimal()) }
}

/// A signed immediate (an `i64` expression) written in hex.
pub fn signed(value: &TokenStream) -> TokenStream {
    quote! { Operand::Immediate(Immediate::signed(#value)) }
}

/// `value` (`width` bits) sign-extended to `i64`.
pub fn sign_extend(value: &TokenStream, width: u32) -> TokenStream {
    let shift = lit(64 - width);
    quote! { ((((#value) as u64) << #shift).cast_signed() >> #shift) }
}

/// A shift of `kind` (a `ShiftKind` variant) by `amount`.
pub fn shift(kind: &str, amount: &TokenStream) -> TokenStream {
    let kind = format_ident!("{kind}");
    quote! { Operand::Shift(Shift { kind: ShiftKind::#kind, amount: (#amount) as u8 }) }
}

/// A named operand of `kind` (a `NameKind` variant).
pub fn named(kind: &str, name: &str) -> TokenStream {
    let kind = format_ident!("{kind}");
    quote! { Operand::Named(Named { kind: NameKind::#kind, name: #name }) }
}

/// A piece of a mnemonic: text, or a choice whose text depends on fields.
#[derive(Debug)]
pub enum MnemonicPiece {
    /// Fixed text, lower case.
    Text(String),
    /// Text by value: the field expression and the text per value.
    Choice(TokenStream, Vec<String>),
}

/// What the generator needs of one form's syntax.
pub struct Syntax {
    /// The mnemonic's pieces.
    pub mnemonic: Vec<MnemonicPiece>,
    /// Code pushing the operands.
    pub operands: TokenStream,
    /// The slots that push operands, in order: each slot's key and code.
    pub slots: Vec<(String, TokenStream)>,
}

/// A form: an encoding's own syntax or one of its aliases.
pub struct Form<'a> {
    /// `ENCODING` or `ENCODING__ALIAS`.
    pub name: String,
    /// The encoding's group path (`sve/sve_maskimm`).
    pub path: &'a str,
    /// The encoding.
    pub instruction: &'a Instruction,
    /// The template.
    pub assembly: &'a [Piece],
    /// Its `encoded_in`.
    pub encoded_in: &'a BTreeMap<String, Vec<String>>,
}

/// The parts of a template: the mnemonic's symbols, then the slots.
struct Parts<'a> {
    mnemonic: Vec<&'a Piece>,
    slots: Vec<Vec<&'a Piece>>,
}

/// Renders symbols as Arm writes the syntax, collecting the displays met.
struct Renderer<'a> {
    rules: &'a BTreeMap<String, AssemblyRule>,
    displays: Vec<&'a str>,
    /// The rules being expanded: a rule met again inside itself (the
    /// recursive tile lists of SME `ZERO { <mask> }`) renders as `...`.
    active: Vec<&'a str>,
}

impl<'a> Renderer<'a> {
    const fn new(rules: &'a BTreeMap<String, AssemblyRule>) -> Self {
        Self {
            rules,
            displays: Vec::new(),
            active: Vec::new(),
        }
    }

    fn pieces(&mut self, pieces: &'a [Piece]) -> String {
        pieces.iter().map(|piece| self.piece(piece)).collect()
    }

    fn piece(&mut self, piece: &'a Piece) -> String {
        let id = match piece {
            Piece::Literal(text) => return text.clone(),
            Piece::Rule(id) => id.as_str(),
        };
        match id {
            "SPACE" | "OPT_SPACE" => return " ".to_owned(),
            "COMMA" => return ", ".to_owned(),
            "hash" => return "#".to_owned(),
            "UInteger" | "SInteger" | "Real" => return "<n>".to_owned(),
            _ => {}
        }
        if self.active.contains(&id) {
            return "...".to_owned();
        }
        self.active.push(id);
        let text = self.rule(id);
        self.active.pop();
        text
    }

    fn rule(&mut self, id: &'a str) -> String {
        match self.rules.get(id) {
            Some(
                AssemblyRule::Rule {
                    display: Some(display),
                    ..
                }
                | AssemblyRule::Choice {
                    display: Some(display),
                    ..
                },
            ) if display.starts_with('<') => {
                self.displays.push(display);
                display.clone()
            }
            Some(AssemblyRule::Rule { symbols, .. }) => self.pieces(symbols),
            Some(AssemblyRule::Choice { choices, display }) => {
                // A choice written as its alternatives (`{2}`, `{PH}`) is
                // still encoded in fields: record its display.
                if let Some(display) = display {
                    self.displays.push(display);
                }
                let rendered: Vec<String> =
                    choices.iter().map(|choice| self.pieces(choice)).collect();
                if rendered.iter().all(|text| text.trim().is_empty()) {
                    return if rendered.iter().any(|text| !text.is_empty()) {
                        " ".to_owned()
                    } else {
                        String::new()
                    };
                }
                let present: Vec<&String> =
                    rendered.iter().filter(|text| !text.is_empty()).collect();
                let joined = present
                    .iter()
                    .map(|text| text.as_str())
                    .collect::<Vec<_>>()
                    .join("|");
                if present.len() < rendered.len() {
                    format!("{{{joined}}}")
                } else if present.len() > 1 {
                    format!("({joined})")
                } else {
                    joined
                }
            }
            Some(AssemblyRule::Token { default, .. }) => default.clone().unwrap_or_default(),
            None => format!("<?{id}>"),
        }
    }
}

/// Whether `id` names a choice with an alternative that writes nothing and
/// one that starts with a comma or space: an optional trailing part.
fn optional(rules: &BTreeMap<String, AssemblyRule>, id: &str) -> bool {
    let Some(AssemblyRule::Choice { choices, .. }) = rules.get(id) else {
        return false;
    };
    let mut writer = Renderer::new(rules);
    let texts: Vec<String> = choices.iter().map(|choice| writer.pieces(choice)).collect();
    texts.iter().any(String::is_empty)
        && texts.iter().any(|text| {
            (text.starts_with(", ") || text.starts_with(' ')) && !text.trim().is_empty()
        })
}

fn split<'a>(rules: &BTreeMap<String, AssemblyRule>, assembly: &'a [Piece]) -> Parts<'a> {
    let mut mnemonic = Vec::new();
    let mut slots: Vec<Vec<&Piece>> = Vec::new();
    let mut in_mnemonic = true;
    let mut current: Vec<&Piece> = Vec::new();
    // Brackets and braces open: a memory operand or register list is one
    // slot, commas and optional parts inside it included.
    let mut depth = 0usize;
    // Whether the last piece closed a slot that opened with `[`: a comma
    // after it continues the slot with a post-index offset
    // (`[<Xn|SP>], #<simm>`).
    let mut closed_memory = false;
    for piece in assembly {
        let after_memory = std::mem::take(&mut closed_memory);
        let id = match piece {
            Piece::Rule(id) => Some(id.as_str()),
            Piece::Literal(text) => {
                for c in text.chars() {
                    match c {
                        '[' | '{' => depth += 1,
                        ']' | '}' => depth = depth.saturating_sub(1),
                        _ => {}
                    }
                }
                closed_memory = depth == 0
                    && text.ends_with(']')
                    && matches!(current.first(), Some(Piece::Literal(first)) if first.starts_with('['));
                None
            }
        };
        if in_mnemonic {
            if id == Some("SPACE") {
                in_mnemonic = false;
                continue;
            }
            if !id.is_some_and(|id| optional(rules, id)) {
                mnemonic.push(piece);
                continue;
            }
            in_mnemonic = false;
        }
        match id {
            Some("COMMA") if depth == 0 && !after_memory => {
                slots.push(std::mem::take(&mut current));
            }
            Some(id) if depth == 0 && optional(rules, id) => {
                if !current.is_empty() {
                    slots.push(std::mem::take(&mut current));
                }
                slots.push(vec![piece]);
            }
            _ => current.push(piece),
        }
    }
    if !current.is_empty() {
        slots.push(current);
    }
    Parts { mnemonic, slots }
}

/// The value-named alternatives of every choice reachable from `pieces`,
/// by display.
fn value_names(
    rules: &BTreeMap<String, AssemblyRule>,
    instruction: &Instruction,
    encoded_in: &BTreeMap<String, Vec<String>>,
    pieces: &[&Piece],
) -> BTreeMap<String, Vec<(Vec<Pattern>, String)>> {
    let mut out = BTreeMap::new();
    let mut pending: Vec<&Piece> = pieces.to_vec();
    let mut seen = BTreeSet::new();
    while let Some(piece) = pending.pop() {
        let Piece::Rule(id) = piece else { continue };
        if !seen.insert(id.as_str()) {
            continue;
        }
        match rules.get(id) {
            Some(AssemblyRule::Rule { symbols, .. }) => pending.extend(symbols),
            Some(AssemblyRule::Choice { display, choices }) => {
                for choice in choices {
                    pending.extend(choice);
                }
                let Some(display) = display else { continue };
                let Some(fields) = encoded_in.get(display) else {
                    continue;
                };
                let Some(widths) = fields
                    .iter()
                    .map(|f| cond::field(&instruction.encoding, f).map(|(_, w)| w))
                    .collect::<Option<Vec<u32>>>()
                else {
                    continue;
                };
                let names: Vec<(Vec<Pattern>, String)> = choices
                    .iter()
                    .filter_map(|choice| match choice.as_slice() {
                        [Piece::Rule(alternative)] => {
                            let values = value_named(alternative, &widths)?;
                            let mut renderer = Renderer::new(rules);
                            let text = renderer.pieces(choice).to_ascii_lowercase();
                            Some((values, text))
                        }
                        _ => None,
                    })
                    .collect();
                if names.len() == choices.len() && !names.is_empty() {
                    out.insert(display.clone(), names);
                }
            }
            Some(AssemblyRule::Token { .. }) | None => {}
        }
    }
    out
}

/// The entry for `slot` producing text (`text`) or operands, if any; fails
/// on equally specific entries.
fn lookup(slot: &Slot<'_>, text: bool) -> Result<Option<&'static Symbol>> {
    let mut best: Option<&'static Symbol> = None;
    let tables = TABLES.iter().filter(|(prefixes, _)| {
        prefixes.is_empty() || prefixes.iter().any(|prefix| under(slot.path, prefix))
    });
    for symbol in tables.flat_map(|(_, symbols)| symbols.iter()) {
        if symbol.key != slot.key
            || matches!(symbol.build, Build::Text(_)) != text
            || (!symbol.fields.is_empty() && symbol.fields != slot.fields.as_slice())
            || (!symbol.forms.is_empty() && !symbol.forms.contains(&slot.form))
        {
            continue;
        }
        match best {
            Some(other) if other.rank() == symbol.rank() => {
                return Err(format!(
                    "{}: two equally specific symbols for `{}` ({:?})",
                    slot.form, slot.key, slot.fields
                )
                .into());
            }
            Some(other) if other.rank() > symbol.rank() => {}
            _ => best = Some(symbol),
        }
    }
    Ok(best)
}

/// Collects keys without entries, for one error listing them all.
#[derive(Default)]
pub struct Missing(BTreeMap<String, Vec<String>>);

impl Missing {
    fn add(&mut self, slot: &Slot<'_>) {
        let key = format!("`{}` fields {:?}", slot.key, slot.fields);
        let forms = self.0.entry(key).or_default();
        if forms.len() < 6 {
            forms.push(slot.form.to_owned());
        }
    }

    /// Fails listing every missing key, if any.
    pub fn check(self) -> Result<()> {
        if self.0.is_empty() {
            return Ok(());
        }
        let mut message = format!(
            "{} symbol keys of done groups have no entry:\n",
            self.0.len()
        );
        for (key, forms) in &self.0 {
            let _ = writeln!(message, "  {key}: {}", forms.join(", "));
        }
        Err(message.into())
    }
}

impl<'a> Form<'a> {
    fn slot<'s>(
        &'s self,
        rules: &'s BTreeMap<String, AssemblyRule>,
        pieces: &[&'s Piece],
    ) -> Slot<'s> {
        let mut renderer = Renderer::new(rules);
        let key: String = pieces.iter().map(|piece| renderer.piece(piece)).collect();
        let key = key
            .split(' ')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let key = key.replace("{ ", "{").replace("( ", "(").replace("| ", "|");
        let mut fields: Vec<String> = Vec::new();
        for display in &renderer.displays {
            for field in self.encoded_in.get(*display).into_iter().flatten() {
                if !fields.contains(field) {
                    fields.push(field.clone());
                }
            }
        }
        Slot {
            key: key.trim().to_owned(),
            form: &self.name,
            path: self.path,
            instruction: self.instruction,
            fields,
            names: value_names(rules, self.instruction, self.encoded_in, pieces),
            encoded_in: self.encoded_in,
        }
    }

    /// The form's mnemonic and operand code, or `None` with the missing
    /// keys recorded.
    pub fn syntax(
        &self,
        rules: &'a BTreeMap<String, AssemblyRule>,
        missing: &mut Missing,
    ) -> Result<Option<Syntax>> {
        let parts = split(rules, self.assembly);
        let mut complete = true;
        let mut mnemonic = Vec::new();
        for piece in &parts.mnemonic {
            if let Piece::Literal(text) = piece {
                mnemonic.push(MnemonicPiece::Text(text.to_ascii_lowercase()));
                continue;
            }
            let slot = self.slot(rules, &[piece]);
            if slot.key.is_empty() {
                continue;
            }
            if let Some(Symbol {
                build: Build::Text(names),
                ..
            }) = lookup(&slot, true)?
            {
                let (value, _) = slot.value()?;
                mnemonic.push(MnemonicPiece::Choice(
                    value,
                    names.iter().map(|name| (*name).to_owned()).collect(),
                ));
            } else {
                missing.add(&slot);
                complete = false;
            }
        }
        let mut code = TokenStream::new();
        let mut slots = Vec::new();
        for pieces in &parts.slots {
            let slot = self.slot(rules, pieces);
            if slot.key.is_empty() {
                continue;
            }
            if let Some(Symbol {
                build: Build::Operands(build),
                ..
            }) = lookup(&slot, false)?
            {
                let built = build(&slot)?;
                code.extend(built.clone());
                slots.push((slot.key, built));
            } else {
                missing.add(&slot);
                complete = false;
            }
        }
        Ok(complete.then_some(Syntax {
            mnemonic,
            operands: code,
            slots,
        }))
    }
}
