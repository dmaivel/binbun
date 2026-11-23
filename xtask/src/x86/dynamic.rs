//! XED's dynamic decode (`generated/dynamic.rs`): the nonterminals that run
//! before identification (the spine's `OSZ_NONTERM`, `ASZ_NONTERM`), the
//! ones in an instruction's pattern (`MODRM()`, `SIMM8()`, `DF64()`, ...),
//! and the lookup nonterminals of its operands (`GPRv_R()`, `XMM_B()`, ...).
//!
//! Each nonterminal becomes a function over the decoder state. Its rule is
//! picked by a `match` on the fields its rules test (XED requires the rules
//! to be disjoint, checked here); the rule then calls the nonterminals in
//! its pattern, then performs its bindings in order (XED's `dec_dyn.py`):
//! a lookup calls the nonterminal and copies its `OUTREG`, a constant is
//! stored, an `error` rule fails with a general error and does nothing
//! else, and `XED_REG_ERROR` fails with a bad-register error. No rule
//! matching fails too, unless the nonterminal has an `otherwise` rule.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use binbun_xed::StateMacros;
use binbun_xed::fields::{DecoderIo, Field};
use binbun_xed::operands::{Operand, Value};
use binbun_xed::pattern::{Pattern, Test};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use super::forms::Instruction;
use super::grammar::{self, Grammar, Rule};
use super::identify::{Allowed, PACKED_BITS, packed_allowed, values_pattern};
use super::ild::{SIZE_POINTS, size_values};
use super::operands::{Added, parse_added};
use super::output;
use super::state::{Kind, StateField, UNREAD, ident_for};
use crate::Result;
use crate::codegen::{GeneratedFile, XED_NOTICE, count, lit};
use crate::naming::ident;

mod partial;

pub use partial::{Code, Known, bail, emit_match};

/// Compiles XED's nonterminals to Rust: as functions over the decoder state
/// (the reference decoder, [`generate`]), or specialised inline over a local
/// state where some fields are known (the fast path, [`partial`]).
pub struct Compiler<'g, 'a> {
    grammar: &'g Grammar<'a>,
    fields: HashMap<&'g str, &'g StateField>,
    widths: HashMap<&'g str, u32>,
    skipped: BTreeSet<&'g str>,
    registers: BTreeSet<String>,
    /// Register numbers (as in the generated `Register`), by XED name.
    register_numbers: HashMap<String, u16>,
    /// Nonterminals to compile, by name, with their function names.
    names: BTreeMap<String, Ident>,
    pending: Vec<String>,
    /// Register lookups compiled to tables (`None`: not a pure lookup), by
    /// nonterminal.
    lookups: HashMap<String, Option<Lookup>>,
    lookup_tables: Vec<TokenStream>,
    /// The fast path's tables, and their names by element type and values.
    partial_tables: Vec<TokenStream>,
    partial_names: HashMap<String, Ident>,
}

/// A register lookup compiled to a table.
#[derive(Debug, Clone)]
struct Lookup {
    /// Reads the entry `v`: a register number, or [`LOOKUP_ERROR`] plus
    /// an error code, with the index of the side bindings above bit 16.
    entry: TokenStream,
    /// Performs the side bindings of `v`, if the table has any.
    side: TokenStream,
    /// Whether some entry is an error.
    fallible: bool,
}

/// What a pure register lookup gives for one combination of its inputs
/// (besides constants bound to other fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Register(u16),
    /// XED's `XED_REG_ERROR`.
    BadRegister,
    /// An `error` rule, or no rule.
    Invalid,
}

/// Lookup-table entries at or above this are errors (the low byte is the
/// error code); below, register numbers.
const LOOKUP_ERROR: u16 = 0x8000;
/// Inputs a lookup table may be indexed by, in bits.
const LOOKUP_BITS: u32 = 10;

/// The values some fields can hold whenever a nonterminal or operand runs:
/// the effective operand and address sizes (set first, by `part1`, and only
/// ever bound to 1-3) and the mode and stack mode (set by the length
/// decoder). A lookup entry outside them cannot be reached, so its error
/// needs no check. [`check_domains`] verifies the sizes' claims.
const DOMAINS: [(&str, u64, u64); 4] = [
    ("EOSZ", 1, 3),
    ("EASZ", 1, 3),
    ("MODE", 0, 2),
    ("SMODE", 0, 2),
];

/// Whether every field of `env` with a [`DOMAINS`] entry holds a value in it.
fn in_domains(env: &BTreeMap<&str, u64>) -> bool {
    DOMAINS.iter().all(|&(field, low, high)| {
        env.get(field)
            .is_none_or(|value| (low..=high).contains(value))
    })
}

/// Checks [`DOMAINS`]' effective sizes: every binding, and the `part1`
/// table, stays within them.
fn check_domains(grammar: &Grammar<'_>, part1: &[(&str, Vec<u64>)]) -> Result<()> {
    for &(field, low, high) in &DOMAINS[..2] {
        let bound = grammar.bound_values(field)?;
        let tabled = part1
            .iter()
            .filter(|(f, _)| *f == field)
            .flat_map(|(_, values)| values.iter());
        if let Some(value) = bound
            .iter()
            .chain(tabled)
            .find(|v| !(low..=high).contains(*v))
        {
            return Err(format!("{field} can be {value}, outside {low}-{high}").into());
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "one argument per parsed datafile or earlier generator result"
)]
pub fn generate(
    instructions: &[Instruction<'_>],
    added: &[Vec<Added>],
    macros: &StateMacros<'_>,
    grammar: &Grammar<'_>,
    spine: &[&str],
    state_fields: &[StateField],
    fields: &[Field<'_>],
    registers: &[String],
) -> Result<(GeneratedFile, Chains)> {
    let mut compiler = Compiler::new(grammar, state_fields, fields, registers);

    // Before identification: the spine, minus prefixes and the instruction
    // table itself.
    let part1 = part1(spine);
    // Size-only nonterminals become table lookups; they cannot fail and read
    // only size-point fields, which no part1 nonterminal sets, so they go
    // first.
    let mut part1_tables = Vec::new();
    let mut part1_lookups = Vec::new();
    let mut part1_calls = Vec::new();
    let mut part1_values = Vec::new();
    for nt in &part1 {
        if let Some((field, values)) = tabulate(grammar, nt) {
            part1_values.push((field, values.iter().map(|&v| u64::from(v)).collect()));
            let table = format_ident!("{}", nt.to_uppercase());
            let field = ident_for(field);
            let values = values.iter().map(|&v| lit(v));
            part1_tables.push(quote!(static #table: [u8; #SIZE_POINTS] = [#(#values),*];));
            part1_lookups.push(quote!(s.#field = #table[point];));
        } else {
            part1_calls.push(compiler.call(nt)?);
        }
    }
    let part1_body = chain(&part1_calls);
    check_domains(grammar, &part1_values)?;
    let part1_point = (!part1_lookups.is_empty()).then(|| quote!(let point = s.size_point();));

    // Per instruction: the pattern's nonterminals, then the operands.
    let mut pattern_chains: Vec<TokenStream> = Vec::new();
    let mut pattern_index: HashMap<String, usize> = HashMap::new();
    let mut operand_chains: Vec<TokenStream> = Vec::new();
    let mut operand_index: HashMap<String, usize> = HashMap::new();
    let mut pattern_of = Vec::with_capacity(instructions.len());
    let mut operands_of = Vec::with_capacity(instructions.len());
    for (instruction, added) in instructions.iter().zip(added) {
        let Pattern::Tokens(tokens) = &instruction.pattern else {
            return Err(format!("line {}: `otherwise` instruction", instruction.line).into());
        };
        let calls = grammar::conditions(tokens).1;
        let steps = calls
            .iter()
            .map(|nt| compiler.call(nt))
            .collect::<Result<Vec<_>>>()?;
        pattern_of.push(intern(
            &mut pattern_chains,
            &mut pattern_index,
            chain(&steps),
        ));

        // XED decodes the operands as written, then those it adds, except
        // pattern captures (`dec_dyn.py`).
        let decoded = parse_added(
            instruction.line,
            added.iter().filter(|a| !a.capture),
            macros,
        )?;
        let steps = instruction
            .operands
            .iter()
            .chain(&decoded)
            .filter_map(|operand| compiler.operand(operand).transpose())
            .collect::<Result<Vec<_>>>()?;
        operands_of.push(intern(
            &mut operand_chains,
            &mut operand_index,
            chain(&steps),
        ));
    }

    let mut functions = Vec::new();
    while let Some(nt) = compiler.pending.pop() {
        functions.push(compiler.function(&nt)?);
    }
    let lookup_tables = &compiler.lookup_tables;

    let pattern_fns = (0..pattern_chains.len()).map(|i| format_ident!("pattern_{i}"));
    let operand_fns = (0..operand_chains.len()).map(|i| format_ident!("operands_{i}"));
    let define = |(body, name): (&TokenStream, Ident)| {
        if body.is_empty() {
            quote!(#[inline] pub fn #name(_: &mut State) {})
        } else {
            quote!(pub fn #name(s: &mut State) { #body })
        }
    };
    let pattern_defs = pattern_chains.iter().zip(pattern_fns.clone()).map(define);
    let operand_defs = operand_chains.iter().zip(operand_fns.clone()).map(define);
    let index_type = |n: usize| if n <= 256 { quote!(u8) } else { quote!(u16) };
    let (pattern_type, operand_type) = (
        index_type(pattern_chains.len()),
        index_type(operand_chains.len()),
    );
    let chains = Chains {
        patterns: pattern_of
            .iter()
            .map(|&i| format_ident!("pattern_{i}"))
            .collect(),
        operands: operands_of
            .iter()
            .map(|&i| format_ident!("operands_{i}"))
            .collect(),
        empty_patterns: pattern_of
            .iter()
            .map(|&i| pattern_chains[i].is_empty())
            .collect(),
        empty_operands: operands_of
            .iter()
            .map(|&i| operand_chains[i].is_empty())
            .collect(),
    };
    let pattern_of = pattern_of.iter().map(|&i| lit(i as u64));
    let operands_of = operands_of.iter().map(|&i| lit(i as u64));
    let (pattern_count, operand_count, instruction_count) = (
        count(pattern_chains.len()),
        count(operand_chains.len()),
        count(instructions.len()),
    );

    let tokens = quote! {
        use crate::generated::state::State;
        use crate::{DecodeError, Register};

        /// The nonterminals that run before identification.
        #[inline]
        pub fn part1(s: &mut State) {
            #part1_point
            #(#part1_lookups)*
            #part1_body
        }

        #(#part1_tables)*

        /// The nonterminals of instruction `number`'s pattern.
        pub fn pattern(s: &mut State, number: u16) {
            let index = usize::from(number - 1);
            PATTERNS[usize::from(PATTERN_OF[index])](s);
        }

        /// The operand lookups of instruction `number`.
        pub fn operands(s: &mut State, number: u16) {
            let index = usize::from(number - 1);
            OPERANDS[usize::from(OPERANDS_OF[index])](s);
        }

        static PATTERN_OF: [#pattern_type; #instruction_count] = [#(#pattern_of),*];
        static OPERANDS_OF: [#operand_type; #instruction_count] = [#(#operands_of),*];
        static PATTERNS: [fn(&mut State); #pattern_count] = [#(#pattern_fns),*];
        static OPERANDS: [fn(&mut State); #operand_count] = [#(#operand_fns),*];

        #(#pattern_defs)*
        #(#operand_defs)*
        #(#functions)*
        #(#lookup_tables)*
    };
    let file = GeneratedFile {
        path: output("dynamic"),
        notice: XED_NOTICE,
        docs: vec!["XED's nonterminals as functions over the decoder state.".to_owned()],
        tokens,
    };
    Ok((file, chains))
}

/// Per instruction (number minus one): its pattern and operand chain
/// functions, and whether they do nothing.
#[derive(Debug)]
pub struct Chains {
    pub patterns: Vec<Ident>,
    pub operands: Vec<Ident>,
    pub empty_patterns: Vec<bool>,
    pub empty_operands: Vec<bool>,
}

/// The spine's nonterminals that run before identification: all but the
/// prefixes and the instruction table itself.
pub fn part1<'a>(spine: &[&'a str]) -> Vec<&'a str> {
    spine
        .iter()
        .copied()
        .filter(|nt| *nt != "PREFIXES" && !nt.contains("INSTRUCTIONS") && !nt.contains("SPLITTER"))
        .collect()
}

/// A nonterminal that sets one field to a constant chosen by the size
/// point alone (`OSZ_NONTERM`: `EOSZ` from `MODE`, `66`, `REX.W`): the
/// field and its value at every size point. `None` for anything else
/// (other conditions, calls, several bindings, errors).
fn tabulate<'a>(grammar: &Grammar<'a>, nt: &str) -> Option<(&'a str, [u8; SIZE_POINTS])> {
    let rules = grammar.rules(nt).ok()?;
    let field = rules.first()?.bindings.first()?.name;
    let simple = rules.iter().all(|rule| {
        rule.calls.is_empty()
            && !rule.scans_bytes
            && matches!(rule.bindings.as_slice(), [b] if b.name == field && matches!(b.value, Value::Number(_)))
    });
    if !simple {
        return None;
    }
    size_values(grammar, &[nt], field)
        .ok()
        .map(|values| (field, values))
}

/// A sequence of steps that stops at the first error.
fn chain(steps: &[TokenStream]) -> TokenStream {
    let count = steps.len();
    let checks = steps.iter().enumerate().map(|(i, step)| {
        if i + 1 == count {
            quote!(#step)
        } else {
            quote!(#step if s.error != 0 { return; })
        }
    });
    quote!(#(#checks)*)
}

fn intern(
    bodies: &mut Vec<TokenStream>,
    index: &mut HashMap<String, usize>,
    body: TokenStream,
) -> usize {
    *index.entry(body.to_string()).or_insert_with(|| {
        bodies.push(body);
        bodies.len() - 1
    })
}

impl<'a> Compiler<'_, 'a> {
    pub fn new<'g>(
        grammar: &'g Grammar<'a>,
        state_fields: &'g [StateField],
        fields: &'g [Field<'_>],
        registers: &[String],
    ) -> Compiler<'g, 'a> {
        Compiler {
            grammar,
            fields: state_fields.iter().map(|f| (f.xed.as_str(), f)).collect(),
            widths: fields.iter().map(|f| (f.name, f.width)).collect(),
            skipped: fields
                .iter()
                .filter(|f| f.decoder == DecoderIo::Skip || UNREAD.contains(&f.name))
                .map(|f| f.name)
                .collect(),
            registers: registers.iter().cloned().collect(),
            register_numbers: registers
                .iter()
                .zip(1u16..)
                .map(|(name, number)| (name.clone(), number))
                .collect(),
            names: BTreeMap::new(),
            pending: Vec::new(),
            lookups: HashMap::new(),
            lookup_tables: Vec::new(),
            partial_tables: Vec::new(),
            partial_names: HashMap::new(),
        }
    }

    /// A call of nonterminal `nt`, queueing it for compilation.
    fn call(&mut self, nt: &str) -> Result<TokenStream> {
        let name = if let Some(name) = self.names.get(nt) {
            name.clone()
        } else {
            self.grammar.rules(nt)?;
            let name = ident(&format!("nt_{}", nt.to_ascii_lowercase()))?;
            if self.names.values().any(|other| *other == name) {
                return Err(format!("two nonterminals become {name}").into());
            }
            self.names.insert(nt.to_owned(), name.clone());
            self.pending.push(nt.to_owned());
            name
        };
        Ok(quote!(#name(s);))
    }

    /// The register lookup `nt` as a table, if it is pure (its rules only
    /// pick a register, an error, or another pure lookup, and bind
    /// constants, by fields of at most [`LOOKUP_BITS`] bits together).
    fn lookup(&mut self, nt: &str) -> Result<Option<Lookup>> {
        if let Some(known) = self.lookups.get(nt) {
            return Ok(known.clone());
        }
        let mut inputs = BTreeSet::new();
        let entry = if self.lookup_inputs(nt, &mut inputs, 0)? {
            self.lookup_table(nt, &inputs)?
        } else {
            None
        };
        self.lookups.insert(nt.to_owned(), entry.clone());
        Ok(entry)
    }

    /// Collects the fields the lookup `nt` reads; false if it is not pure.
    fn lookup_inputs(&self, nt: &str, inputs: &mut BTreeSet<&'a str>, depth: u32) -> Result<bool> {
        let rules = self.grammar.rules(nt)?;
        if depth > 8 {
            return Ok(false);
        }
        for rule in rules {
            let Some(conditions) = &rule.conditions else {
                return Ok(false);
            };
            if !rule.calls.is_empty() || rule.scans_bytes {
                return Ok(false);
            }
            for condition in conditions {
                if self.skipped.contains(condition.field) {
                    continue;
                }
                if self.widths.get(condition.field).is_none_or(|&w| w > 8) {
                    return Ok(false);
                }
                inputs.insert(condition.field);
            }
            if rule
                .bindings
                .iter()
                .any(|b| matches!(b.value, Value::Error(_)))
            {
                continue;
            }
            let mut outputs = 0;
            for binding in &rule.bindings {
                match (&binding.value, binding.name) {
                    (Value::Register(_), "OUTREG") => outputs += 1,
                    (Value::Lookup(inner), "OUTREG") => {
                        outputs += 1;
                        if !self.lookup_inputs(inner, inputs, depth + 1)? {
                            return Ok(false);
                        }
                    }
                    (Value::Number(_), name) if name != "OUTREG" && binding.test != Test::Ne => {
                        if self
                            .field(name)?
                            .is_some_and(|f| !matches!(f.kind, Kind::Unsigned | Kind::Signed))
                        {
                            return Ok(false);
                        }
                    }
                    _ => return Ok(false),
                }
            }
            if outputs != 1 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The table of the pure lookup `nt` over `inputs` (first input in the
    /// highest bits), or `None` if it is too large.
    fn lookup_table(&mut self, nt: &str, inputs: &BTreeSet<&'a str>) -> Result<Option<Lookup>> {
        let widths: Vec<u32> = inputs.iter().map(|f| self.widths[*f]).collect();
        let bits: u32 = widths.iter().sum();
        if bits > LOOKUP_BITS {
            return Ok(None);
        }
        // (outcome, side index, reachable)
        let mut entries = Vec::with_capacity(1 << bits);
        // Distinct side bindings; index 0 is none.
        let mut sides: Vec<Vec<(&'a str, u64)>> = vec![Vec::new()];
        for index in 0..1u64 << bits {
            let mut env = BTreeMap::new();
            let mut shift = bits;
            for (field, width) in inputs.iter().zip(&widths) {
                shift -= width;
                env.insert(*field, index >> shift & ((1 << width) - 1));
            }
            let mut side = Vec::new();
            let outcome = self.evaluate_lookup(nt, &env, &mut side)?;
            side.sort_unstable();
            let side_index = sides.iter().position(|s| *s == side).unwrap_or_else(|| {
                sides.push(side);
                sides.len() - 1
            });
            entries.push((outcome, side_index, in_domains(&env)));
        }
        let wide = sides.len() > 1;
        let fallible = entries
            .iter()
            .any(|&(outcome, _, reachable)| reachable && !matches!(outcome, Outcome::Register(_)));
        let error = lit(u64::from(LOOKUP_ERROR));
        let element = if wide { quote!(u32) } else { quote!(u16) };
        let entries = entries.iter().map(|&(outcome, side, _)| match outcome {
            Outcome::Register(number) => {
                let number = lit(u64::from(number) | (side as u64) << 16);
                quote!(#number)
            }
            Outcome::BadRegister => quote!(#error | DecodeError::BadRegister as #element),
            Outcome::Invalid => quote!(#error | DecodeError::Invalid as #element),
        });
        let table = format_ident!("LOOKUP_{}", nt.to_ascii_uppercase());
        let count = count(1 << bits);
        self.lookup_tables
            .push(quote!(static #table: [#element; #count] = [#(#entries),*];));
        let mut index = Vec::new();
        let mut shift = bits;
        for (field, width) in inputs.iter().zip(&widths) {
            shift -= width;
            let ident = &self.fields[*field].ident;
            // Masked to the field's width: the index provably fits the
            // table, so it needs no bounds check.
            let mask = lit((1u64 << width) - 1);
            index.push(if shift == 0 {
                quote!(usize::from(s.#ident & #mask))
            } else {
                let shift = lit(u64::from(shift));
                quote!(usize::from(s.#ident & #mask) << #shift)
            });
        }
        let side = if wide {
            // Each field some side binds, selected without a branch: the
            // side's value, or the field's own where the side has none, as
            // `(field & keep) | value` from constant tables.
            let bound: BTreeSet<&str> = sides.iter().flatten().map(|(name, _)| *name).collect();
            let stores = bound
                .into_iter()
                .map(|name| {
                    let ident = &self
                        .fields
                        .get(name)
                        .ok_or_else(|| format!("{nt}: side binding of unknown field {name}"))?
                        .ident;
                    // Padded to a power of two, so that a mask (not a
                    // bounds check) keeps the index in range.
                    let size = sides.len().next_power_of_two();
                    let values: Vec<Option<u64>> = (0..size)
                        .map(|i| {
                            sides
                                .get(i)
                                .and_then(|side| side.iter().find(|(n, _)| *n == name))
                                .map(|&(_, value)| value)
                        })
                        .collect();
                    let keep = values
                        .iter()
                        .map(|v| if v.is_some() { quote!(0) } else { quote!(!0) });
                    let value = values.iter().map(|v| lit(v.unwrap_or(0)));
                    let mask = lit(size as u64 - 1);
                    Ok(quote! {
                        let side = (v >> 16) as usize & #mask;
                        s.#ident = (s.#ident & [#(#keep),*][side]) | [#(#value),*][side];
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            quote!(#(#stores)*)
        } else {
            TokenStream::new()
        };
        Ok(Some(Lookup {
            entry: quote!(#table[#(#index)|*]),
            side,
            fallible,
        }))
    }

    /// What the pure lookup `nt` gives when fields have the values in `env`,
    /// adding the constants it binds to other fields to `side`.
    fn evaluate_lookup(
        &self,
        nt: &str,
        env: &BTreeMap<&str, u64>,
        side: &mut Vec<(&'a str, u64)>,
    ) -> Result<Outcome> {
        let mut found = None;
        for rule in self.grammar.rules(nt)? {
            let holds = rule
                .conditions
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter(|c| !self.skipped.contains(c.field))
                .all(|c| c.holds(env[c.field]));
            if holds {
                if found.is_some() {
                    return Err(format!("{nt}: overlapping rules").into());
                }
                found = Some(rule);
            }
        }
        let Some(rule) = found else {
            return Ok(Outcome::Invalid);
        };
        if rule
            .bindings
            .iter()
            .any(|b| matches!(b.value, Value::Error(_)))
        {
            return Ok(Outcome::Invalid);
        }
        let mut outcome = None;
        for binding in &rule.bindings {
            match &binding.value {
                Value::Register(register) => {
                    let name = register.trim_start_matches("XED_REG_");
                    outcome = Some(match name {
                        "INVALID" => Outcome::Register(0),
                        "ERROR" => Outcome::BadRegister,
                        _ => Outcome::Register(
                            *self
                                .register_numbers
                                .get(name)
                                .ok_or_else(|| format!("unknown register {register}"))?,
                        ),
                    });
                }
                Value::Lookup(inner) => outcome = Some(self.evaluate_lookup(inner, env, side)?),
                // Encoder-only, as in `binding`.
                Value::Number(_) if binding.name == "ENCODER_PREFERRED" => {}
                // Unread fields need no binding.
                Value::Number(_) if self.skipped.contains(binding.name) => {}
                Value::Number(n) => side.push((binding.name, *n)),
                other @ (Value::Present
                | Value::Error(_)
                | Value::Enumerator(_)
                | Value::Bits(_)) => {
                    return Err(format!("{nt}: {other:?} in a pure lookup").into());
                }
            }
        }
        outcome.ok_or_else(|| format!("{nt}: no register").into())
    }

    fn field(&self, name: &str) -> Result<Option<&StateField>> {
        if self.skipped.contains(name) {
            return Ok(None);
        }
        self.fields
            .get(name)
            .copied()
            .map(Some)
            .ok_or_else(|| format!("unknown field {name}").into())
    }

    /// The step an instruction operand needs at decode time, if any: XED
    /// stores lookups, registers and constants (a bare operand such as
    /// `MEM0` is the constant 1).
    fn operand(&mut self, operand: &Operand<'_>) -> Result<Option<TokenStream>> {
        if matches!(
            operand.value,
            Value::Lookup(_) | Value::Register(_) | Value::Present | Value::Number(_)
        ) {
            self.binding(operand)
        } else {
            Ok(None)
        }
    }

    /// One binding of a rule (or an instruction operand).
    fn binding(&mut self, operand: &Operand<'_>) -> Result<Option<TokenStream>> {
        if operand.name == "ENCODER_PREFERRED" {
            return Ok(None);
        }
        if operand.test == Test::Ne {
            return Err(format!("`{}!=` binding", operand.name).into());
        }
        let Some(field) = self.field(operand.name)? else {
            return Ok(None);
        };
        let (target, kind) = (field.ident.clone(), field.kind);
        Ok(Some(match (&operand.value, kind) {
            (Value::Bits(_), _) => return Ok(None),
            (Value::Lookup(nt), _) => {
                if operand.name != "OUTREG" && kind != Kind::Register {
                    return Err(format!("lookup into non-register field {}", operand.name).into());
                }
                if let Some(Lookup {
                    entry,
                    side,
                    fallible,
                }) = self.lookup(nt)?
                {
                    // `OUTREG` is only read right after a call of a
                    // nonterminal that sets it (below), so a lookup into
                    // another field need not set it too.
                    let store = quote!(s.#target = v as u16;);
                    let error = lit(u64::from(LOOKUP_ERROR));
                    let store = if fallible {
                        quote! {
                            if v & #error == 0 {
                                #store
                            } else {
                                s.error = v as u8;
                            }
                        }
                    } else {
                        store
                    };
                    return Ok(Some(quote!({
                        let v = #entry;
                        #store
                        #side
                    })));
                }
                let call = self.call(nt)?;
                if operand.name == "OUTREG" {
                    call
                } else {
                    quote!(#call s.#target = s.outreg;)
                }
            }
            (Value::Register(register), Kind::Register) => {
                let name = register.trim_start_matches("XED_REG_");
                match name {
                    "INVALID" => quote!(s.#target = 0;),
                    "ERROR" => quote!(s.#target = 0; s.error = DecodeError::BadRegister as u8;),
                    _ if self.registers.contains(name) => {
                        let variant = ident(name)?;
                        quote!(s.#target = Register::#variant as u16;)
                    }
                    _ => return Err(format!("unknown register {register}").into()),
                }
            }
            (Value::Number(n), Kind::Unsigned | Kind::Signed) => {
                let n = lit(*n);
                quote!(s.#target = #n;)
            }
            (Value::Present, Kind::Unsigned) => quote!(s.#target = 1;),
            (value, kind) => {
                return Err(format!("cannot bind {value:?} to {} ({kind:?})", operand.name).into());
            }
        }))
    }

    /// The actions of `rule`.
    fn actions(&mut self, rule: &Rule<'_>) -> Result<TokenStream> {
        if rule
            .bindings
            .iter()
            .any(|op| matches!(op.value, Value::Error(_)))
        {
            return Ok(quote!(s.error = DecodeError::Invalid as u8;));
        }
        let mut steps = rule
            .calls
            .iter()
            .map(|nt| self.call(nt))
            .collect::<Result<Vec<_>>>()?;
        for binding in &rule.bindings {
            steps.extend(self.binding(binding)?);
        }
        Ok(quote!(#(#steps)*))
    }

    fn function(&mut self, nt: &str) -> Result<TokenStream> {
        let name = self.names[nt].clone();
        let rules = self.grammar.rules(nt)?;
        if let Some(rule) = rules.iter().find(|r| r.scans_bytes) {
            return Err(format!(
                "{nt} (line {}) reads bytes, which only the length decoder does",
                rule.line
            )
            .into());
        }
        let otherwise = rules.iter().find(|r| r.conditions.is_none());
        if let Some(rule) = otherwise
            && !rule.bindings.is_empty()
        {
            return Err(format!("{nt}: `otherwise` with bindings (line {})", rule.line).into());
        }
        let candidates = self.candidates(nt, rules)?;
        let keys: BTreeSet<&str> = candidates
            .iter()
            .flat_map(|(_, f)| f.keys().copied())
            .collect();
        if keys.is_empty() {
            let body = match candidates.as_slice() {
                [] => TokenStream::new(),
                [(rule, _)] => self.actions(rule)?,
                _ => return Err(format!("{nt}: several unconditional rules").into()),
            };
            return Ok(if body.is_empty() {
                quote!(fn #name(_: &mut State) {})
            } else {
                quote!(fn #name(s: &mut State) { #body })
            });
        }
        let exprs = keys
            .iter()
            .map(|&f| {
                let field = self
                    .field(f)?
                    .ok_or_else(|| format!("{nt} tests skipped field {f}"))?;
                let ident = &field.ident;
                Ok(quote!(s.#ident))
            })
            .collect::<Result<Vec<_>>>()?;
        let single = exprs.len() == 1;
        let key_widths: Vec<u32> = keys
            .iter()
            .map(|f| self.widths.get(f).copied().unwrap_or(64))
            .collect();
        let key_bits: u32 = key_widths.iter().sum();
        if !single && key_widths.iter().all(|&w| w <= 8) && key_bits <= PACKED_BITS {
            return self.packed_function(
                &name,
                &keys,
                &key_widths,
                &candidates,
                otherwise.is_some(),
            );
        }
        let mut arms = Vec::new();
        for (rule, required) in &candidates {
            let patterns = keys.iter().map(|&field| {
                let width = self.widths.get(field).copied().unwrap_or(64);
                let domain = if width > 8 { u64::MAX } else { 1u64 << width };
                required
                    .get(field)
                    .map_or_else(|| quote!(_), |allowed| values_pattern(allowed, domain))
            });
            let pattern = if single {
                quote!(#(#patterns)*)
            } else {
                quote!((#(#patterns),*))
            };
            let actions = self.actions(rule)?;
            arms.push(quote!(#pattern => { #actions }));
        }
        let fallback = if otherwise.is_some() {
            quote!({})
        } else {
            quote!({
                s.error = DecodeError::Invalid as u8;
            })
        };
        let scrutinee = if single {
            quote!(#(#exprs)*)
        } else {
            quote!((#(#exprs),*))
        };
        Ok(quote! {
            fn #name(s: &mut State) {
                match #scrutinee {
                    #(#arms)*
                    _ => #fallback
                }
            }
        })
    }

    /// The rules of `nt` that have conditions, each with the values it
    /// requires of the fields it tests (skipped fields left out), minus
    /// rules whose conditions contradict each other. Fails if two rules
    /// overlap.
    fn candidates<'r>(
        &self,
        nt: &str,
        rules: &'r [Rule<'a>],
    ) -> Result<Vec<(&'r Rule<'a>, BTreeMap<&'a str, Allowed>)>> {
        let candidates: Vec<(&Rule<'_>, BTreeMap<&str, Allowed>)> = rules
            .iter()
            .filter_map(|rule| rule.conditions.as_ref().map(|c| (rule, c)))
            .map(|(rule, conditions)| {
                let mut required: BTreeMap<&str, Allowed> = BTreeMap::new();
                for condition in conditions {
                    if self.skipped.contains(condition.field) {
                        continue;
                    }
                    let width = *self
                        .widths
                        .get(condition.field)
                        .ok_or_else(|| format!("unknown field {}", condition.field))?;
                    if width > 8 && condition.test == Test::Ne {
                        return Err(format!(
                            "{nt}: `!=` on the {width}-bit field {}",
                            condition.field
                        )
                        .into());
                    }
                    let domain: Allowed = if width > 8 {
                        std::iter::once(condition.value).collect()
                    } else {
                        (0..1u64 << width).collect()
                    };
                    required
                        .entry(condition.field)
                        .or_insert(domain)
                        .retain(|&v| condition.holds(v));
                }
                Ok((rule, required))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            // A rule whose conditions contradict each other never applies.
            .filter(|(_, required)| required.values().all(|allowed| !allowed.is_empty()))
            .collect();
        for (i, (a, fa)) in candidates.iter().enumerate() {
            for (b, fb) in candidates.iter().skip(i + 1) {
                if fa
                    .iter()
                    .all(|(f, allowed)| fb.get(f).is_none_or(|other| !allowed.is_disjoint(other)))
                {
                    return Err(
                        format!("{nt}: rules on lines {} and {} overlap", a.line, b.line).into(),
                    );
                }
            }
        }
        Ok(candidates)
    }

    /// A nonterminal function whose rules are selected by one packed key
    /// of the narrow fields `keys` (first in the highest bits).
    fn packed_function(
        &mut self,
        name: &Ident,
        keys: &BTreeSet<&str>,
        widths: &[u32],
        candidates: &[(&Rule<'_>, BTreeMap<&str, Allowed>)],
        otherwise: bool,
    ) -> Result<TokenStream> {
        let bits: u32 = widths.iter().sum();
        let mut parts = Vec::new();
        let mut shift = bits;
        for (&field, &width) in keys.iter().zip(widths) {
            shift -= width;
            let ident = &self.fields[field].ident;
            let mask = lit((1u64 << width) - 1);
            parts.push(if shift == 0 {
                quote!(u32::from(s.#ident & #mask))
            } else {
                let shift = lit(u64::from(shift));
                quote!(u32::from(s.#ident & #mask) << #shift)
            });
        }
        let mut arms = Vec::new();
        for (rule, required) in candidates {
            let required: Vec<Option<&Allowed>> = keys.iter().map(|f| required.get(f)).collect();
            let pattern = values_pattern(&packed_allowed(widths, &required), 1u64 << bits);
            let actions = self.actions(rule)?;
            arms.push(quote!(#pattern => { #actions }));
        }
        let fallback = if otherwise {
            quote!({})
        } else {
            quote!({
                s.error = DecodeError::Invalid as u8;
            })
        };
        Ok(quote! {
            fn #name(s: &mut State) {
                match #(#parts)|* {
                    #(#arms)*
                    _ => #fallback
                }
            }
        })
    }
}
