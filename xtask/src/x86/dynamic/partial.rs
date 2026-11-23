//! The nonterminal compiler's second output mode, for the 64-bit fast path
//! (`fast.rs`): partial evaluation and local storage.
//!
//! Rules mean what they mean in [`Compiler::function`] and
//! [`Compiler::binding`], with three differences:
//!
//! - **Local storage.** Code is emitted inline into one function per opcode,
//!   over a local `s` that never escapes, so LLVM keeps the fields it uses
//!   in registers. Nothing is called.
//! - **Partial evaluation.** [`Known`] says which values fields can hold
//!   where the code runs. Rules whose conditions contradict it are dropped
//!   and conditions it implies leave the match; a nonterminal or lookup
//!   whose remaining inputs are a few bits becomes tables indexed by them,
//!   or constants when none remain. Code after a write knows the values
//!   written.
//! - **Errors give up** ([`bail`]): the fast path answers only valid
//!   instructions, and returns the reference decoder's answer for every
//!   other, so which error comes first does not matter here.

use std::collections::{BTreeMap, BTreeSet};

use binbun_xed::operands::{Operand, Value};
use binbun_xed::pattern::Test;
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use super::{Compiler, Outcome, tabulate};
use crate::Result;
use crate::codegen::{count, lit};
use crate::x86::grammar::Rule;
use crate::x86::identify::{Allowed, packed_allowed, values_pattern};
use crate::x86::ild::SIZE_POINTS;
use crate::x86::state::Kind;

/// Inputs a specialised table may be indexed by, in bits.
const TABLE_BITS: u32 = 10;

/// Match keys of up to this many bits in all are packed into one integer.
const MATCH_BITS: u32 = 16;

/// The fields of a size point, in the runtime's order (see
/// `ild::size_point`).
const SIZE_FIELDS: [&str; 4] = ["MODE", "OSZ", "ASZ", "REXW"];

/// What generated code knows about fields where it runs: for each field
/// listed, the values it can hold; a field not listed can hold any.
#[derive(Debug, Clone, Default)]
pub struct Known {
    values: BTreeMap<String, Allowed>,
}

impl Known {
    /// `field` holds one of `values`.
    pub fn set(&mut self, field: &str, values: Allowed) {
        self.values.insert(field.to_owned(), values);
    }

    /// `field` holds `value`.
    pub fn set_single(&mut self, field: &str, value: u64) {
        self.set(field, std::iter::once(value).collect());
    }

    /// `field` can hold any value.
    pub fn forget(&mut self, field: &str) {
        self.values.remove(field);
    }

    /// The value of `field`, if only one is possible.
    pub fn single(&self, field: &str) -> Option<u64> {
        match self.values.get(field) {
            Some(values) if values.len() == 1 => values.first().copied(),
            _ => None,
        }
    }

    /// Whether `field` can hold a value of `allowed`.
    pub fn admits(&self, field: &str, allowed: &Allowed) -> bool {
        self.values
            .get(field)
            .is_none_or(|values| !values.is_disjoint(allowed))
    }

    /// Whether every value `field` can hold is in `allowed`.
    pub fn implies(&self, field: &str, allowed: &Allowed) -> bool {
        self.values
            .get(field)
            .is_some_and(|values| values.is_subset(allowed))
    }

    /// Restricts `field` to the values of `allowed`.
    pub fn narrow(&mut self, field: &str, allowed: &Allowed) {
        match self.values.get_mut(field) {
            Some(values) => values.retain(|value| allowed.contains(value)),
            None => self.set(field, allowed.clone()),
        }
    }

    /// What is known after either `self`'s code or `other`'s ran.
    pub fn join(&mut self, other: &Self) {
        self.values
            .retain(|field, values| match other.values.get(field) {
                Some(more) => {
                    values.extend(more);
                    true
                }
                None => false,
            });
    }

    /// The fields with one possible value, and their values.
    fn singles(&self) -> BTreeMap<&str, u64> {
        self.values
            .iter()
            .filter(|(_, values)| values.len() == 1)
            .filter_map(|(field, values)| Some((field.as_str(), *values.first()?)))
            .collect()
    }
}

/// Specialised code: statements over the local `s`, and whether they always
/// return.
#[derive(Debug, Default)]
pub struct Code {
    pub tokens: TokenStream,
    pub diverges: bool,
}

impl Code {
    /// Failing: the reference decoder will report the error.
    fn bail() -> Self {
        Self {
            tokens: bail(),
            diverges: true,
        }
    }

    /// Appends `next`, unless this code always returns before it; returns
    /// whether the code now always returns.
    pub fn then(&mut self, next: Self) -> bool {
        if !self.diverges {
            self.tokens.extend(next.tokens);
            self.diverges = next.diverges;
        }
        self.diverges
    }
}

/// What a table's code does for one combination of its inputs.
enum Row {
    /// The inputs never have these values here.
    Unreachable,
    /// The instruction is not valid (or not handled here).
    Error,
    /// These stores, in order.
    Writes(Vec<(String, u64)>),
}

/// A rule of a nonterminal being specialised: the values it requires of
/// fields not known to have them, and the calls not yet emitted.
#[derive(Clone)]
struct Choice<'g, 'a> {
    rule: &'g Rule<'a>,
    required: BTreeMap<&'a str, Allowed>,
    calls: Vec<&'a str>,
}

/// One input of a table: field and width in bits.
type Input = (String, u32);

impl<'g, 'a> Compiler<'g, 'a> {
    /// The tables the specialised code indexes.
    pub fn partial_tables(&self) -> &[TokenStream] {
        &self.partial_tables
    }

    /// The XED names of every state field.
    pub fn state_fields(&self) -> impl Iterator<Item = &str> {
        self.fields.keys().copied()
    }

    /// The width in bits of XED field `field`.
    pub fn width(&self, field: &str) -> Result<u32> {
        self.widths
            .get(field)
            .copied()
            .ok_or_else(|| format!("unknown field {field}").into())
    }

    /// `s.field` as a match key: the expression and its width in bits.
    pub fn key(&self, field: &str) -> Result<(TokenStream, u32)> {
        let state = self
            .field(field)?
            .ok_or_else(|| format!("key on skipped field {field}"))?;
        let ident = &state.ident;
        Ok((quote!(s.#ident), self.width(field)?))
    }

    /// The nonterminals before identification (`dynamic::part1`),
    /// specialised: the size tables first, then the calls.
    pub fn specialize_part1(&mut self, part1: &[&str], known: &mut Known) -> Result<Code> {
        let mut code = Code::default();
        let mut calls = Vec::new();
        for nt in part1 {
            if let Some((field, values)) = tabulate(self.grammar, nt) {
                let (expr, domain) = self.specialize_size(&values, known)?;
                let ident = &self
                    .field(field)?
                    .ok_or_else(|| format!("{nt} binds skipped field {field}"))?
                    .ident;
                code.then(Code {
                    tokens: quote!(s.#ident = #expr;),
                    diverges: false,
                });
                known.set(field, domain);
            } else {
                calls.push(*nt);
            }
        }
        for nt in calls {
            if code.then(self.specialize_call(nt, known)?) {
                break;
            }
        }
        Ok(code)
    }

    /// A value given at every size point (`values`), where `known` holds:
    /// an expression of type `u8`, and the values it can take.
    pub fn specialize_size(
        &mut self,
        values: &[u8; SIZE_POINTS],
        known: &Known,
    ) -> Result<(TokenStream, Allowed)> {
        let inputs = self
            .unknown(SIZE_FIELDS.iter().copied(), known)
            .ok_or("size fields too wide to tabulate")?;
        let rows = self.rows(&inputs, known, |_, env| {
            let get = |field: &str| env.get(field).copied().unwrap_or(0);
            let point = ((get("MODE") * 2 + get("OSZ")) * 2 + get("ASZ")) * 2 + get("REXW");
            let value = usize::try_from(point)
                .ok()
                .and_then(|point| values.get(point))
                .ok_or("size point out of range")?;
            Ok(Row::Writes(vec![(String::new(), u64::from(*value))]))
        })?;
        let reached: Vec<u64> = rows
            .iter()
            .filter_map(|row| match row {
                Row::Writes(writes) => writes.first().map(|&(_, value)| value),
                Row::Unreachable | Row::Error => None,
            })
            .collect();
        let domain: Allowed = reached.iter().copied().collect();
        if let [value] = domain.iter().copied().collect::<Vec<_>>()[..] {
            let value = lit(value);
            return Ok((quote!(#value), domain));
        }
        let column = rows
            .iter()
            .map(|row| match row {
                Row::Writes(writes) => writes.first().map_or(0, |&(_, value)| value),
                Row::Unreachable | Row::Error => 0,
            })
            .collect::<Vec<_>>();
        let table = self.table(&quote!(u8), &column);
        let key = self.index(&inputs)?;
        Ok((quote!({ #key #table[k] }), domain))
    }

    /// A call of nonterminal `nt`, specialised to `known`, which it updates.
    pub fn specialize_call(&mut self, nt: &str, known: &mut Known) -> Result<Code> {
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
        let choices = self
            .candidates(nt, rules)?
            .into_iter()
            .map(|(rule, required)| Choice {
                rule,
                required,
                calls: rule.calls.clone(),
            })
            .collect();
        self.select(nt, choices, otherwise.is_some(), known)
    }

    /// An instruction operand's step (as [`Compiler::operand`]), specialised.
    pub fn specialize_operand(&mut self, operand: &Operand<'_>, known: &mut Known) -> Result<Code> {
        if matches!(
            operand.value,
            Value::Lookup(_) | Value::Register(_) | Value::Present | Value::Number(_)
        ) {
            self.specialize_binding(operand, known)
        } else {
            Ok(Code::default())
        }
    }

    /// The rule of `choices` that applies, as code: dropping rules `known`
    /// rules out, hoisting calls every rule starts with, tabulating rules
    /// that only bind (all of them, or those the others leave), and
    /// matching on the remaining fields.
    fn select(
        &mut self,
        nt: &str,
        mut choices: Vec<Choice<'g, 'a>>,
        otherwise: bool,
        known: &mut Known,
    ) -> Result<Code> {
        prune(&mut choices, known);
        if choices.is_empty() {
            return Ok(if otherwise {
                Code::default()
            } else {
                Code::bail()
            });
        }
        let mut code = Code::default();
        // A call every rule makes first can run before the choice, if it
        // does not write the fields that decide it. (Not with an
        // `otherwise` rule, which makes no call.)
        while !otherwise && let Some(first) = common_first_call(&choices) {
            let mut written = BTreeSet::new();
            self.writes(first, &mut written, &mut BTreeSet::new())?;
            if !written.is_disjoint(&keys(&choices)) {
                break;
            }
            if code.then(self.specialize_call(first, known)?) {
                return Ok(code);
            }
            for choice in &mut choices {
                choice.calls.remove(0);
            }
            prune(&mut choices, known);
        }
        let all_keys = keys(&choices);
        if all_keys.is_empty() {
            let [choice] = choices.as_slice() else {
                return Err(format!("{nt}: several rules apply").into());
            };
            code.then(self.specialize_actions(choice, known)?);
            return Ok(code);
        }
        let mut called = Vec::new();
        let mut flat = Vec::new();
        for choice in choices {
            if choice.calls.is_empty() && self.only_binds(choice.rule)? {
                flat.push(choice);
            } else {
                called.push(choice);
            }
        }
        if !flat.is_empty()
            && let Some(inputs) = self.flat_inputs(&all_keys, &flat, known)?
        {
            let rows = self.rows(&inputs, known, |this, env| {
                this.select_row(&flat, &called, otherwise, env)
            })?;
            if called.is_empty() {
                code.then(self.emit_rows(&inputs, &rows, known)?);
            } else {
                let mut rest = known.clone();
                let fallback = self.emit_rows(&inputs, &rows, &mut rest)?;
                code.then(self.match_choices(&called, &fallback, &rest, known)?);
            }
            return Ok(code);
        }
        called.extend(flat);
        let fallback = if otherwise {
            Code::default()
        } else {
            Code::bail()
        };
        let rest = known.clone();
        code.then(self.match_choices(&called, &fallback, &rest, known)?);
        Ok(code)
    }

    /// A `match` selecting among `choices` on the fields they test, with
    /// `fallback` (after which `rest` is known) for none; updates `known`.
    fn match_choices(
        &mut self,
        choices: &[Choice<'g, 'a>],
        fallback: &Code,
        rest: &Known,
        known: &mut Known,
    ) -> Result<Code> {
        let fields: Vec<&str> = keys(choices).into_iter().collect();
        let keys = fields
            .iter()
            .map(|field| self.key(field))
            .collect::<Result<Vec<_>>>()?;
        let mut arms = Vec::new();
        let mut after: Option<Known> = (!fallback.diverges).then(|| rest.clone());
        for choice in choices {
            let mut inside = known.clone();
            for (field, allowed) in &choice.required {
                inside.narrow(field, allowed);
            }
            let body = self.specialize_actions(choice, &mut inside)?;
            if !body.diverges {
                match &mut after {
                    Some(after) => after.join(&inside),
                    None => after = Some(inside),
                }
            }
            let required = fields
                .iter()
                .map(|field| choice.required.get(field).cloned())
                .collect();
            arms.push((required, body.tokens));
        }
        let tokens = emit_match(&keys, &arms, &fallback.tokens);
        let diverges = after.is_none();
        if let Some(after) = after {
            *known = after;
        }
        Ok(Code { tokens, diverges })
    }

    /// The calls and bindings of `choice`'s rule.
    fn specialize_actions(&mut self, choice: &Choice<'g, 'a>, known: &mut Known) -> Result<Code> {
        if choice
            .rule
            .bindings
            .iter()
            .any(|b| matches!(b.value, Value::Error(_)))
        {
            return Ok(Code::bail());
        }
        let mut code = Code::default();
        for nt in &choice.calls {
            if code.then(self.specialize_call(nt, known)?) {
                return Ok(code);
            }
        }
        for binding in &choice.rule.bindings {
            if code.then(self.specialize_binding(binding, known)?) {
                break;
            }
        }
        Ok(code)
    }

    /// One binding: stores of constants, or of entries of a table indexed
    /// by the inputs of its lookup that are not known.
    fn specialize_binding(&mut self, operand: &Operand<'_>, known: &mut Known) -> Result<Code> {
        let mut inputs = BTreeSet::new();
        if let Value::Lookup(nt) = operand.value
            && self.field(operand.name)?.is_some()
            && !self.lookup_inputs(nt, &mut inputs, 0)?
        {
            return Err(format!("{}={nt}(): not a pure lookup", operand.name).into());
        }
        let inputs = self
            .unknown(inputs.into_iter(), known)
            .ok_or_else(|| format!("{}: too many inputs to tabulate", operand.name))?;
        let rows = self.rows(&inputs, known, |this, env| {
            let mut writes = Vec::new();
            Ok(if this.evaluate_binding(operand, env, &mut writes)? {
                Row::Writes(writes)
            } else {
                Row::Error
            })
        })?;
        self.emit_rows(&inputs, &rows, known)
    }

    /// Whether `rule` only binds (constants, registers and pure lookups).
    fn only_binds(&self, rule: &Rule<'a>) -> Result<bool> {
        for binding in &rule.bindings {
            if let Value::Lookup(nt) = binding.value
                && self.field(binding.name)?.is_some()
                && !self.lookup_inputs(nt, &mut BTreeSet::new(), 0)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The inputs of a table for `flat`'s rules: the fields deciding the
    /// rule and those their lookups read, less those known; `None` if too
    /// many.
    fn flat_inputs(
        &self,
        keys: &BTreeSet<&'a str>,
        flat: &[Choice<'g, 'a>],
        known: &Known,
    ) -> Result<Option<Vec<Input>>> {
        let mut fields: BTreeSet<&'a str> = keys.clone();
        for choice in flat {
            for binding in &choice.rule.bindings {
                if let Value::Lookup(nt) = binding.value
                    && self.field(binding.name)?.is_some()
                    && !self.lookup_inputs(nt, &mut fields, 0)?
                {
                    return Ok(None);
                }
            }
        }
        Ok(self.unknown(fields.into_iter(), known))
    }

    /// The fields of `fields` with more than one possible value, with their
    /// widths; `None` if one is wider than a byte or all are more than
    /// [`TABLE_BITS`].
    fn unknown<'f>(
        &self,
        fields: impl Iterator<Item = &'f str>,
        known: &Known,
    ) -> Option<Vec<Input>> {
        let mut inputs = Vec::new();
        let mut bits = 0;
        for field in fields {
            if known.single(field).is_some() {
                continue;
            }
            let width = *self.widths.get(field)?;
            if width > 8 {
                return None;
            }
            bits += width;
            inputs.push((field.to_owned(), width));
        }
        (bits <= TABLE_BITS).then_some(inputs)
    }

    /// The row of a table over `flat`'s rules for the inputs in `env`.
    fn select_row<'e>(
        &self,
        flat: &[Choice<'g, 'a>],
        called: &[Choice<'g, 'a>],
        otherwise: bool,
        env: &mut BTreeMap<&'e str, u64>,
    ) -> Result<Row>
    where
        'a: 'e,
    {
        let holds = |choice: &Choice<'g, 'a>| {
            choice
                .required
                .iter()
                .all(|(field, allowed)| env.get(field).is_some_and(|v| allowed.contains(v)))
        };
        if called.iter().any(holds) {
            return Ok(Row::Unreachable);
        }
        let Some(choice) = flat.iter().find(|choice| holds(choice)) else {
            return Ok(if otherwise {
                Row::Writes(Vec::new())
            } else {
                Row::Error
            });
        };
        let mut writes = Vec::new();
        for binding in &choice.rule.bindings {
            if !self.evaluate_binding(binding, env, &mut writes)? {
                return Ok(Row::Error);
            }
        }
        Ok(Row::Writes(writes))
    }

    /// Performs `operand` (as [`Compiler::binding`] would) on the fields in
    /// `env`, recording the stores in `writes`; false if it fails.
    fn evaluate_binding<'e>(
        &self,
        operand: &Operand<'e>,
        env: &mut BTreeMap<&'e str, u64>,
        writes: &mut Vec<(String, u64)>,
    ) -> Result<bool>
    where
        'a: 'e,
    {
        if operand.name == "ENCODER_PREFERRED" {
            return Ok(true);
        }
        if operand.test == Test::Ne {
            return Err(format!("`{}!=` binding", operand.name).into());
        }
        if matches!(operand.value, Value::Error(_)) {
            return Ok(false);
        }
        let Some(field) = self.field(operand.name)? else {
            return Ok(true);
        };
        let mut store = |env: &mut BTreeMap<&'e str, u64>, name: &'e str, value: u64| {
            env.insert(name, value);
            writes.push((name.to_owned(), value));
        };
        match (&operand.value, field.kind) {
            (Value::Bits(_), _) => {}
            (Value::Lookup(nt), _) => {
                let mut side = Vec::new();
                match self.evaluate_lookup(nt, env, &mut side)? {
                    Outcome::Register(number) => store(env, operand.name, u64::from(number)),
                    Outcome::BadRegister | Outcome::Invalid => return Ok(false),
                }
                for (name, value) in side {
                    store(env, name, value);
                }
            }
            (Value::Register(register), Kind::Register) => {
                let name = register.trim_start_matches("XED_REG_");
                let number = match name {
                    "INVALID" => 0,
                    "ERROR" => return Ok(false),
                    _ => *self
                        .register_numbers
                        .get(name)
                        .ok_or_else(|| format!("unknown register {register}"))?,
                };
                store(env, operand.name, u64::from(number));
            }
            (Value::Number(n), Kind::Unsigned | Kind::Signed) => store(env, operand.name, *n),
            (Value::Present, Kind::Unsigned) => store(env, operand.name, 1),
            (value, kind) => {
                return Err(format!("cannot bind {value:?} to {} ({kind:?})", operand.name).into());
            }
        }
        Ok(true)
    }

    /// The rows of a table over `inputs` (first in the highest bits): what
    /// `row` gives with the known fields and each combination of inputs that
    /// `known` allows.
    fn rows<'e>(
        &self,
        inputs: &'e [Input],
        known: &'e Known,
        mut row: impl FnMut(&Self, &mut BTreeMap<&'e str, u64>) -> Result<Row>,
    ) -> Result<Vec<Row>> {
        let base = known.singles();
        let bits: u32 = inputs.iter().map(|(_, width)| width).sum();
        let mut rows = Vec::with_capacity(1 << bits);
        for index in 0..1u64 << bits {
            let mut env = base.clone();
            let mut shift = bits;
            let mut reachable = true;
            for (field, width) in inputs {
                shift -= width;
                let value = index >> shift & ((1 << width) - 1);
                reachable &= known.admits(field, &std::iter::once(value).collect());
                env.insert(field.as_str(), value);
            }
            rows.push(if reachable {
                row(self, &mut env)?
            } else {
                Row::Unreachable
            });
        }
        Ok(rows)
    }

    /// `let k = ...;`: the index of a table over `inputs`. Each input is
    /// masked to its width, so the index is in bounds.
    fn index(&self, inputs: &[Input]) -> Result<TokenStream> {
        let bits: u32 = inputs.iter().map(|(_, width)| width).sum();
        let mut shift = bits;
        let mut parts = Vec::new();
        for (field, width) in inputs {
            shift -= width;
            let ident = &self
                .field(field)?
                .ok_or_else(|| format!("table input {field} is skipped"))?
                .ident;
            let mask = lit((1u64 << width) - 1);
            parts.push(if shift == 0 {
                quote!(usize::from(s.#ident & #mask))
            } else {
                let shift = lit(u64::from(shift));
                quote!(usize::from(s.#ident & #mask) << #shift)
            });
        }
        Ok(quote!(let k = #(#parts)|*;))
    }

    /// The code of a table: fail on error rows, then store each field some
    /// row writes (a constant if every reachable row stores the same).
    fn emit_rows(&mut self, inputs: &[Input], rows: &[Row], known: &mut Known) -> Result<Code> {
        let reached: Vec<&Row> = rows
            .iter()
            .filter(|row| !matches!(row, Row::Unreachable))
            .collect();
        if reached.iter().all(|row| matches!(row, Row::Error)) {
            return Ok(Code::bail());
        }
        let mut columns: Vec<&str> = Vec::new();
        for row in &reached {
            if let Row::Writes(writes) = row {
                for (field, _) in writes {
                    if !columns.contains(&field.as_str()) {
                        columns.push(field);
                    }
                }
            }
        }
        let mut statements = Vec::new();
        // Whether a table is read (at index `k`).
        let mut indexed = false;
        if reached.iter().any(|row| matches!(row, Row::Error)) {
            let errors: Vec<u64> = rows
                .iter()
                .map(|row| u64::from(matches!(row, Row::Error)))
                .collect();
            let table = self.table(&quote!(bool), &errors);
            let bail = bail();
            statements.push(quote!(if #table[k] { #bail }));
            indexed = true;
        }
        for column in columns {
            let prior = known.single(column);
            // Per row: the value stored, or the field's own if none is.
            let stored = |row: &Row| match row {
                Row::Writes(writes) => writes
                    .iter()
                    .rev()
                    .find(|(field, _)| field == column)
                    .map(|&(_, value)| value)
                    .or(prior),
                Row::Unreachable | Row::Error => Some(0),
            };
            let values: Vec<Option<u64>> = rows.iter().map(stored).collect();
            let reached_values: Vec<Option<u64>> = rows
                .iter()
                .filter(|row| matches!(row, Row::Writes(_)))
                .map(stored)
                .collect();
            let state = self
                .field(column)?
                .ok_or_else(|| format!("store to skipped field {column}"))?;
            let (ident, ty) = (state.ident.clone(), state.ty.clone());
            let distinct: Allowed = reached_values.iter().flatten().copied().collect();
            if reached_values.iter().all(Option::is_some) {
                if let [value] = distinct.iter().copied().collect::<Vec<_>>()[..] {
                    let value = lit(value);
                    statements.push(quote!(s.#ident = #value;));
                } else {
                    let column = values.iter().map(|v| v.unwrap_or(0)).collect::<Vec<_>>();
                    let table = self.table(&ty, &column);
                    statements.push(quote!(s.#ident = #table[k];));
                    indexed = true;
                }
                known.set(column, distinct);
            } else {
                // Some rows leave a field of unknown value as it is.
                let keep: Vec<u64> = values
                    .iter()
                    .map(|v| if v.is_some() { 0 } else { u64::MAX })
                    .collect();
                let value: Vec<u64> = values.iter().map(|v| v.unwrap_or(0)).collect();
                let keep = self.table(&ty, &keep);
                let value = self.table(&ty, &value);
                statements.push(quote!(s.#ident = (s.#ident & #keep[k]) | #value[k];));
                indexed = true;
                known.forget(column);
            }
        }
        let tokens = if indexed {
            let index = self.index(inputs)?;
            quote!({ #index #(#statements)* })
        } else {
            quote!(#(#statements)*)
        };
        Ok(Code {
            tokens,
            diverges: false,
        })
    }

    /// The name of a table of `ty` holding `values` (`u64::MAX` is all
    /// ones), shared by every user.
    fn table(&mut self, ty: &TokenStream, values: &[u64]) -> Ident {
        let key = format!("{ty}:{values:?}");
        if let Some(name) = self.partial_names.get(&key) {
            return name.clone();
        }
        let name = format_ident!("T{}", self.partial_names.len());
        let is_bool = ty.to_string() == "bool";
        let entries = values.iter().map(|&value| {
            if is_bool {
                if value == 0 {
                    quote!(false)
                } else {
                    quote!(true)
                }
            } else if value == u64::MAX {
                quote!(!0)
            } else {
                let value = lit(value);
                quote!(#value)
            }
        });
        let length = count(values.len());
        self.partial_tables
            .push(quote!(static #name: [#ty; #length] = [#(#entries),*];));
        self.partial_names.insert(key, name.clone());
        name
    }

    /// Collects every field `nt` (and what it calls or looks up) may write.
    fn writes(
        &self,
        nt: &str,
        written: &mut BTreeSet<&'a str>,
        seen: &mut BTreeSet<String>,
    ) -> Result<()> {
        if !seen.insert(nt.to_owned()) {
            return Ok(());
        }
        for rule in self.grammar.rules(nt)? {
            for binding in &rule.bindings {
                written.insert(binding.name);
                if let Value::Lookup(inner) = binding.value {
                    self.writes(inner, written, seen)?;
                }
            }
            for call in &rule.calls {
                self.writes(call, written, seen)?;
            }
        }
        Ok(())
    }
}

/// Drops the choices `known` rules out, and the requirements it implies.
fn prune(choices: &mut Vec<Choice<'_, '_>>, known: &Known) {
    choices.retain(|choice| {
        choice
            .required
            .iter()
            .all(|(field, allowed)| known.admits(field, allowed))
    });
    for choice in choices {
        choice
            .required
            .retain(|field, allowed| !known.implies(field, allowed));
    }
}

/// The fields the choices test.
fn keys<'a>(choices: &[Choice<'_, 'a>]) -> BTreeSet<&'a str> {
    choices
        .iter()
        .flat_map(|choice| choice.required.keys().copied())
        .collect()
}

/// The call every choice makes first, if they agree.
fn common_first_call<'a>(choices: &[Choice<'_, 'a>]) -> Option<&'a str> {
    let first = *choices.first()?.calls.first()?;
    choices
        .iter()
        .all(|choice| choice.calls.first() == Some(&first))
        .then_some(first)
}

/// The statement that gives up on an encoding: it returns the reference
/// decoder's answer (the generated function's `F::fallback`).
pub fn bail() -> TokenStream {
    quote!(return F::fallback(bytes, address);)
}

/// A `match` on `keys` (expressions and widths in bits) with one arm per
/// `arms` entry (the values each key must have, `None` for any) and
/// `fallback` for none. Narrow keys are packed into one integer.
pub fn emit_match(
    keys: &[(TokenStream, u32)],
    arms: &[(Vec<Option<Allowed>>, TokenStream)],
    fallback: &TokenStream,
) -> TokenStream {
    let widths: Vec<u32> = keys.iter().map(|(_, width)| *width).collect();
    let bits: u32 = widths.iter().sum();
    if widths.iter().all(|&width| width <= 8) && bits <= MATCH_BITS {
        let mut shift = bits;
        let parts = keys.iter().map(|(expr, width)| {
            shift -= width;
            let mask = lit((1u64 << width) - 1);
            if shift == 0 {
                quote!(u32::from(#expr & #mask))
            } else {
                let shift = lit(u64::from(shift));
                quote!(u32::from(#expr & #mask) << #shift)
            }
        });
        let parts: Vec<TokenStream> = parts.collect();
        let arms = arms.iter().map(|(required, body)| {
            let required: Vec<Option<&Allowed>> = required.iter().map(Option::as_ref).collect();
            let pattern = values_pattern(&packed_allowed(&widths, &required), 1u64 << bits);
            quote!(#pattern => { #body })
        });
        return quote! {
            match #(#parts)|* {
                #(#arms)*
                _ => { #fallback }
            }
        };
    }
    let exprs = keys.iter().map(|(expr, _)| expr);
    let arms = arms.iter().map(|(required, body)| {
        let patterns = required.iter().zip(&widths).map(|(allowed, &width)| {
            let domain = if width > 8 { u64::MAX } else { 1u64 << width };
            allowed
                .as_ref()
                .map_or_else(|| quote!(_), |allowed| values_pattern(allowed, domain))
        });
        quote!((#(#patterns),*) => { #body })
    });
    quote! {
        match (#(#exprs),*) {
            #(#arms)*
            _ => { #fallback }
        }
    }
}
