//! Instruction identification (`generated/identify.rs`), XED's static decode.
//!
//! After length decoding, the instruction is one of the patterns of its
//! `(encoding space, map, opcode)`. Each pattern requires values of some
//! fields (`MOD=3`, `REG[0b010]`, `REP=3`, `VL=1`, ...); XED requires the
//! patterns of one opcode to be disjoint over the fields any of them uses,
//! which is checked here, so each opcode becomes a `match` whose arm order
//! does not matter. `EOSZ`/`EASZ` keys come from the opcode's size
//! nonterminals, like widths in `ild.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use binbun_xed::fields::{DecoderIo, Field};
use binbun_xed::pattern::Pattern;
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use super::forms::Instruction;
use super::grammar::{self, Grammar};
use super::ild::{self, Map, SIZE_POINTS};
use super::output;
use super::state;
use crate::Result;
use crate::codegen::{GeneratedFile, XED_NOTICE, count, lit};

/// A pattern's requirement on one field: the allowed values.
pub type Allowed = BTreeSet<u64>;

/// One candidate of an opcode.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub line: u32,
    /// Instruction number (index into the instruction table plus one).
    pub number: u16,
    /// Required fields.
    pub fields: BTreeMap<String, Allowed>,
    /// The nonterminals that set `EOSZ` and `EASZ` before identification
    /// tests them.
    pub eosz: Vec<String>,
    pub easz: Vec<String>,
}

/// An opcode's identification function and the instructions it can find.
#[derive(Debug)]
pub struct Bin {
    pub space: u8,
    pub map: u8,
    pub opcode: u8,
    pub function: Ident,
    pub numbers: Vec<u16>,
    pub candidates: Vec<Candidate>,
}

pub fn generate(
    instructions: &[Instruction<'_>],
    grammar: &Grammar<'_>,
    maps: &[Map<'_>],
    fields: &[Field<'_>],
) -> Result<(GeneratedFile, Vec<Bin>)> {
    let widths: BTreeMap<&str, u32> = fields.iter().map(|f| (f.name, f.width)).collect();
    let skipped: BTreeSet<&str> = fields
        .iter()
        .filter(|f| f.decoder == DecoderIo::Skip)
        .map(|f| f.name)
        .collect();
    let operand_size_setters = grammar.setters("EOSZ");
    let address_size_setters = grammar.setters("EASZ");

    let mut bins: BTreeMap<(u8, u8, u8), Vec<Candidate>> = BTreeMap::new();
    for (index, instruction) in instructions.iter().enumerate() {
        let Pattern::Tokens(tokens) = &instruction.pattern else {
            return Err(format!("line {}: `otherwise` instruction", instruction.line).into());
        };
        let (space, map, opcodes) = ild::locate(
            instruction.line,
            instruction.text,
            &instruction.pattern,
            maps,
        )?;
        let mut required: BTreeMap<String, Allowed> = BTreeMap::new();
        for condition in grammar::conditions(tokens).0 {
            if matches!(condition.field, "MAP" | "VEXVALID") || skipped.contains(condition.field) {
                continue;
            }
            let width = *widths
                .get(condition.field)
                .ok_or_else(|| format!("unknown field {}", condition.field))?;
            let domain: Allowed = (0..1u64 << width.min(8)).collect();
            let allowed = required.entry(condition.field.to_owned()).or_insert(domain);
            allowed.retain(|&value| condition.holds(value));
        }
        let number = u16::try_from(index + 1)?;
        let sequence = |set, implied| {
            ild::sequence(instruction.text, set, Some(implied))
                .into_iter()
                .map(str::to_owned)
                .collect()
        };
        for opcode in opcodes {
            bins.entry((space, map, opcode))
                .or_default()
                .push(Candidate {
                    line: instruction.line,
                    number,
                    fields: required.clone(),
                    eosz: sequence(&operand_size_setters, "OSZ_NONTERM"),
                    easz: sequence(&address_size_setters, "ASZ_NONTERM"),
                });
        }
    }

    let mut sizes: Vec<[u8; SIZE_POINTS]> = Vec::new();
    let mut functions = Vec::new();
    let mut tables: BTreeMap<(u8, u8), Vec<Option<Ident>>> = BTreeMap::new();
    let mut list = Vec::new();
    for ((space, map, opcode), candidates) in &bins {
        check_disjoint(*space, *map, *opcode, candidates)?;
        let name = format_ident!("id_{space}_{map}_{opcode:02x}");
        functions.push(identify_fn(
            &name, candidates, &widths, grammar, &mut sizes,
        )?);
        tables
            .entry((*space, *map))
            .or_insert_with(|| vec![None; 256])[usize::from(*opcode)] = Some(name.clone());
        list.push(Bin {
            space: *space,
            map: *map,
            opcode: *opcode,
            function: name,
            numbers: candidates.iter().map(|c| c.number).collect(),
            candidates: candidates.clone(),
        });
    }

    let table_statics = tables.iter().map(|((space, map), slots)| {
        let name = format_ident!("ID_{space}_{map}");
        let slots = slots
            .iter()
            .map(|slot| slot.as_ref().map_or_else(|| quote!(none), |f| quote!(#f)));
        quote!(static #name: [Identify; 256] = [#(#slots),*];)
    });
    let dispatch = tables.keys().map(|(space, map)| {
        let name = format_ident!("ID_{space}_{map}");
        let (space, map) = (lit(*space), lit(*map));
        quote!((#space, #map) => #name[usize::from(s.nominal_opcode)](s),)
    });
    let size_tables = sizes.iter().map(|table| {
        let table = table.iter().map(|&v| lit(v));
        quote!([#(#table),*])
    });
    let size_count = count(sizes.len());

    let tokens = quote! {
        use crate::generated::state::State;

        type Identify = fn(&State) -> u16;

        /// The number of the instruction the length-decoded `s` is (an
        /// index into the instruction table plus one), or 0 for none.
        pub fn identify(s: &State) -> u16 {
            match (s.vexvalid, s.map) {
                #(#dispatch)*
                _ => 0,
            }
        }

        fn none(_: &State) -> u16 {
            0
        }

        /// `EOSZ` or `EASZ` by size point, for opcodes whose patterns
        /// depend on them.
        static SIZES: [[u8; 24]; #size_count] = [#(#size_tables),*];

        #(#table_statics)*
        #(#functions)*
    };
    let file = GeneratedFile {
        path: output("identify"),
        notice: XED_NOTICE,
        docs: vec![
            "Instruction identification: which instruction a length-decoded encoding is."
                .to_owned(),
        ],
        tokens,
    };
    Ok((file, list))
}

/// XED rejects opcodes whose patterns overlap; so do we.
fn check_disjoint(space: u8, map: u8, opcode: u8, candidates: &[Candidate]) -> Result<()> {
    for (i, a) in candidates.iter().enumerate() {
        for b in candidates.iter().skip(i + 1) {
            let overlap = a.fields.iter().all(|(field, allowed)| {
                b.fields
                    .get(field)
                    .is_none_or(|other| !allowed.is_disjoint(other))
            });
            if overlap {
                return Err(format!(
                    "space {space} map {map} opcode {opcode:#04x}: patterns on lines {} and {} overlap",
                    a.line, b.line
                )
                .into());
            }
        }
    }
    Ok(())
}

/// The Rust expression reading XED field `field` from `s: &State`. Before
/// identification `EOSZ`/`EASZ` come from the opcode's size nonterminals
/// (locals). (XED's special `RM` getter for opcodes without ModRM is
/// disabled: such patterns use `SRM`.)
fn field_expr(field: &str) -> TokenStream {
    match field {
        "EOSZ" => quote!(eosz),
        "EASZ" => quote!(easz),
        _ => {
            let name = state::ident_for(field);
            quote!(s.#name)
        }
    }
}

/// Nonterminal rules on fields of up to this many bits in all are selected
/// by one packed key (one jump table, not a compare per field): measured
/// fewer branches, misses and cycles. Identification measured faster with
/// per-field matches, so it keeps them.
pub const PACKED_BITS: u32 = 10;

/// The packed keys (first field in the highest bits) whose fields of
/// `widths` take values `required` allows (`None`: any).
pub fn packed_allowed(widths: &[u32], required: &[Option<&Allowed>]) -> Allowed {
    let mut keys: Allowed = std::iter::once(0).collect();
    for (&width, allowed) in widths.iter().zip(required) {
        let values: Vec<u64> = allowed.map_or_else(
            || (0..1u64 << width).collect(),
            |a| a.iter().copied().collect(),
        );
        keys = keys
            .iter()
            .flat_map(|&key| values.iter().map(move |&v| key << width | v))
            .collect();
    }
    keys
}

/// A match pattern for `allowed` out of `0..domain`.
pub fn values_pattern(allowed: &Allowed, domain: u64) -> TokenStream {
    if allowed.len() as u64 >= domain {
        return quote!(_);
    }
    if allowed.is_empty() {
        // Impossible requirement; never matched.
        return quote!(256..);
    }
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for &value in allowed {
        match ranges.last_mut() {
            Some((_, end)) if *end + 1 == value => *end = value,
            _ => ranges.push((value, value)),
        }
    }
    let alternatives = ranges.iter().map(|&(start, end)| {
        let (start, end) = (lit(start), lit(end));
        if start.to_string() == end.to_string() {
            quote!(#start)
        } else {
            quote!(#start..=#end)
        }
    });
    quote!(#(#alternatives)|*)
}

fn identify_fn(
    name: &Ident,
    candidates: &[Candidate],
    widths: &BTreeMap<&str, u32>,
    grammar: &Grammar<'_>,
    sizes: &mut Vec<[u8; SIZE_POINTS]>,
) -> Result<TokenStream> {
    let keys: BTreeSet<&str> = candidates
        .iter()
        .flat_map(|c| c.fields.keys().map(String::as_str))
        .collect();
    let mut prelude = TokenStream::new();
    for (field, pick) in [("EOSZ", 0), ("EASZ", 1)] {
        if !keys.contains(field) {
            continue;
        }
        let sequences: BTreeSet<&Vec<String>> = candidates
            .iter()
            .map(|c| if pick == 0 { &c.eosz } else { &c.easz })
            .collect();
        let [sequence] = sequences.into_iter().collect::<Vec<_>>()[..] else {
            let lines: String = candidates.iter().fold(String::new(), |mut s, c| {
                let _ = write!(s, " {}", c.line);
                s
            });
            return Err(format!("{name}: patterns{lines} disagree on {field} nonterminals").into());
        };
        let sequence: Vec<&str> = sequence.iter().map(String::as_str).collect();
        let values = ild::size_values(grammar, &sequence, field)?;
        let index = sizes.iter().position(|t| *t == values).unwrap_or_else(|| {
            sizes.push(values);
            sizes.len() - 1
        });
        let index = lit(u64::try_from(index)?);
        let variable = format_ident!("{}", field.to_ascii_lowercase());
        prelude.extend(quote!(let #variable = SIZES[#index][s.size_point()];));
    }

    if keys.is_empty() {
        let [candidate] = candidates else {
            return Err(format!("{name}: several patterns with no requirements").into());
        };
        let number = lit(candidate.number);
        return Ok(quote!(#[inline] pub fn #name(_: &State) -> u16 { #number }));
    }
    let exprs: Vec<TokenStream> = keys.iter().map(|field| field_expr(field)).collect();
    let single = exprs.len() == 1;
    let arms = candidates.iter().map(|candidate| {
        let patterns = keys.iter().map(|&field| {
            let domain = 1u64 << widths.get(field).copied().unwrap_or(8).min(8);
            candidate
                .fields
                .get(field)
                .map_or_else(|| quote!(_), |allowed| values_pattern(allowed, domain))
        });
        let number = lit(candidate.number);
        if single {
            quote!(#(#patterns)* => #number,)
        } else {
            quote!((#(#patterns),*) => #number,)
        }
    });
    let scrutinee = if single {
        quote!(#(#exprs)*)
    } else {
        quote!((#(#exprs),*))
    };
    Ok(quote! {
        #[inline]
        pub fn #name(s: &State) -> u16 {
            #prelude
            match #scrutinee {
                #(#arms)*
                _ => 0,
            }
        }
    })
}
