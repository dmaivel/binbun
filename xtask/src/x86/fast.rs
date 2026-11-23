//! The 64-bit fast path (`generated/fast.rs`): one function per opcode of
//! the legacy maps 0, `0F`, `0F 38` and `0F 3A` that decodes a legacy
//! encoding of it in 64-bit mode with the decoder state in registers.
//! (Every opcode rather than only the hottest hundred: measured faster
//! still, at 0.9 GB more peak compile memory.)
//!
//! Each function starts after the runtime has read the prefixes (at most
//! one of `66`/`F2`/`F3`, then at most one REX) and the opcode; it runs the
//! length decoder's tail for the opcode's constant entry, then the spine,
//! identification, and the chosen instruction's pattern and operand
//! nonterminals, all emitted inline by the nonterminal compiler in its
//! partial-evaluation mode (`dynamic/partial.rs`), from the same grammar as
//! the reference decoder. What is known going in: 64-bit mode, no segment
//! override, `67`, `LOCK`, REX2 or vector prefix, the map and the opcode.
//! Every error gives up: the function returns the reference decoder's
//! answer (`Finish::fallback`), so that its result is written once, where
//! the caller wants it.

use std::collections::{BTreeMap, BTreeSet};

use binbun_xed::StateMacros;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::dynamic::{Code, Compiler, Known, bail, emit_match, part1};
use super::forms::Instruction;
use super::identify::{Allowed, Bin, Candidate};
use super::ild::{self, OpcodeEntries};
use super::operands::{Added, parse_added};
use super::output;
use crate::Result;
use crate::codegen::{GeneratedFile, XED_NOTICE, count, hex, lit};

/// Number of legacy maps reached without a trailing opcode: 0, `0F`,
/// `0F 38`, `0F 3A`.
const MAPS: usize = 4;

/// Fields the runtime's prefix reading sets, with the values they can
/// take.
const PREFIX_FIELDS: [(&str, &[u64]); 14] = [
    ("OSZ", &[0, 1]),
    ("PREFIX66", &[0, 1]),
    ("ILD_F2", &[0, 1]),
    ("ILD_F3", &[0, 1]),
    ("FIRST_F2F3", &[0, 2, 3]),
    ("LAST_F2F3", &[0, 2, 3]),
    ("REP", &[0, 2, 3]),
    ("REX", &[0, 1]),
    ("REXW", &[0, 1]),
    ("REXR", &[0, 1]),
    ("REXX", &[0, 1]),
    ("REXB", &[0, 1]),
    ("NREXES", &[0, 1]),
    ("NPREFIXES", &[0, 1, 2]),
];

/// Fields the length decoder's tail may set (besides `ERROR`, which is
/// checked after it).
const TAIL_FIELDS: [&str; 14] = [
    "MOD",
    "REG",
    "RM",
    "DISP_WIDTH",
    "HAS_SIB",
    "SIBSCALE",
    "SIBINDEX",
    "SIBBASE",
    "DISP",
    "IMM_WIDTH",
    "IMM1_BYTES",
    "UIMM0",
    "UIMM1",
    "ESRC",
];

/// Fields the runtime sets to constants before the tail (`State::load`'s
/// and those of 64-bit mode).
const CONSTANT_FIELDS: [(&str, u64); 6] = [
    ("MODE", 2),
    ("SMODE", 2),
    ("P4", 1),
    ("TZCNT", 1),
    ("LZCNT", 1),
    ("CET", 1),
];

/// What the generator needs besides the nonterminal compiler.
pub struct Inputs<'x, 'a> {
    pub spine: &'x [&'a str],
    pub entries: &'x OpcodeEntries,
    pub bins: &'x [Bin],
    pub instructions: &'x [Instruction<'a>],
    pub added: &'x [Vec<Added>],
    pub macros: &'x StateMacros<'a>,
    pub grammar: &'x super::grammar::Grammar<'a>,
}

pub fn generate(compiler: &mut Compiler<'_, '_>, inputs: &Inputs<'_, '_>) -> Result<GeneratedFile> {
    let bins: BTreeMap<(u8, u8), &Bin> = inputs
        .bins
        .iter()
        .filter(|bin| bin.space == 0)
        .map(|bin| ((bin.map, bin.opcode), bin))
        .collect();
    let part1 = part1(inputs.spine);
    let mut functions = Vec::new();
    let mut slots = vec![vec![None; 256]; MAPS];
    let mut handled = Vec::new();
    let opcodes: Vec<(u8, u8)> = bins
        .keys()
        .copied()
        .filter(|&(map, opcode)| usize::from(map) < MAPS && reachable(map, opcode))
        .collect();
    for &(map, opcode) in &opcodes {
        let bin = bins
            .get(&(map, opcode))
            .ok_or_else(|| format!("map {map} opcode {opcode:#04x}: no instruction"))?;
        let entry = inputs
            .entries
            .get(&(0, map))
            .and_then(|entries| entries.get(usize::from(opcode)))
            .copied()
            .ok_or_else(|| format!("map {map}: no length entries"))?;
        let name = format_ident!("f_{map}_{opcode:02x}");
        let Some(body) = opcode_body(compiler, inputs, &part1, map, opcode, entry, bin)
            .map_err(|e| format!("map {map} opcode {opcode:#04x}: {e}"))?
        else {
            // No instruction in 64-bit mode.
            continue;
        };
        let (map_lit, opcode_lit, entry_lit) = (lit(map), hex(opcode), lit(entry));
        let bail = bail();
        functions.push(quote! {
            pub fn #name<F: Finish>(window: &[u8; 32], head: Head, address: u64, bytes: &[u8]) -> F::Output {
                let mut s = State::default();
                s.fast_start(head, #map_lit, #opcode_lit);
                s.fast_tail(window, #entry_lit);
                if s.error != 0 {
                    #bail
                }
                #body
            }
        });
        if let Some(slot) = slots
            .get_mut(usize::from(map))
            .and_then(|slots| slots.get_mut(usize::from(opcode)))
        {
            *slot = Some(name);
        }
        handled.push(quote!((#map_lit, #opcode_lit)));
    }
    let maps = slots.iter().map(|slots| {
        let slots = slots.iter().map(|slot| {
            slot.as_ref()
                .map_or_else(|| quote!(unhandled::<F>), |name| quote!(#name::<F>))
        });
        quote!([#(#slots),*])
    });
    let tables = compiler.partial_tables();
    let (maps_count, handled_count) = (count(MAPS), count(handled.len()));
    let tokens = quote! {
        use crate::fast::{Fast, Finish, FlowOnly, Full, Head, unhandled};
        use crate::generated::state::State;

        /// Legacy maps reached without a trailing opcode: 0, `0F`, `0F 38`,
        /// `0F 3A`.
        pub const MAPS: usize = #maps_count;

        /// The fast path of each legacy map's opcodes, finishing with `F`.
        pub const fn table<F: Finish>() -> [[Fast<F>; 256]; MAPS] {
            [#(#maps),*]
        }

        /// The fast path of each legacy map's opcodes, for full decoding.
        pub static FULL: [[Fast<Full>; 256]; MAPS] = table::<Full>();

        /// The fast path of each legacy map's opcodes, for flow-only
        /// decoding.
        pub static FLOW: [[Fast<FlowOnly>; 256]; MAPS] = table::<FlowOnly>();

        /// The opcodes with a fast path, as `(map, opcode)`.
        pub const HANDLED: [(u8, u8); #handled_count] = [#(#handled),*];

        #(#functions)*
        #(#tables)*
    };
    Ok(GeneratedFile {
        path: output("fast"),
        notice: XED_NOTICE,
        docs: vec![
            "The 64-bit fast path: per-opcode decoders specialised to 64-bit mode and".to_owned(),
            "legacy encodings, with the decoder state in locals.".to_owned(),
        ],
        tokens,
    })
}

/// Whether the runtime's prefix reading can reach `opcode` of `map` (not
/// a prefix, an escape, or a byte starting an encoding prefix).
fn reachable(map: u8, opcode: u8) -> bool {
    match map {
        0 => !matches!(
            opcode,
            0x0f | 0x26 | 0x2e | 0x36 | 0x3e | 0x40..=0x4f | 0x62 | 0x64..=0x67 | 0x8f | 0xc4 | 0xc5
                | 0xd5 | 0xf0 | 0xf2 | 0xf3
        ),
        1 => !matches!(opcode, 0x0f | 0x38 | 0x3a),
        2 | 3 => true,
        _ => false,
    }
}

/// What is known after the runtime has read the prefixes, `opcode` of
/// `map` and the tail of length entry `entry`.
fn entry_known(compiler: &Compiler<'_, '_>, map: u8, opcode: u8) -> Result<Known> {
    let mut known = Known::default();
    let fields: BTreeSet<String> = compiler.state_fields().map(str::to_owned).collect();
    for field in &fields {
        known.set_single(field, 0);
    }
    let constants = CONSTANT_FIELDS.iter().copied().chain([
        ("MAP", u64::from(map)),
        ("NOMINAL_OPCODE", u64::from(opcode)),
        ("SRM", u64::from(opcode & 7)),
    ]);
    for (field, value) in constants {
        if !fields.contains(field) {
            return Err(format!("{field} is not a state field").into());
        }
        known.set_single(field, value);
    }
    for (field, values) in PREFIX_FIELDS {
        if !fields.contains(field) {
            return Err(format!("{field} is not a state field").into());
        }
        known.set(field, values.iter().copied().collect());
    }
    for field in TAIL_FIELDS {
        if !fields.contains(field) {
            return Err(format!("{field} is not a state field").into());
        }
        known.forget(field);
    }
    Ok(known)
}

/// The rest of opcode `opcode`'s function, after the tail: the spine,
/// identification and the chosen instruction's nonterminals; every arm
/// returns. `None` if no instruction has the opcode in 64-bit mode.
fn opcode_body(
    compiler: &mut Compiler<'_, '_>,
    inputs: &Inputs<'_, '_>,
    part1: &[&str],
    map: u8,
    opcode: u8,
    entry: u16,
    bin: &Bin,
) -> Result<Option<TokenStream>> {
    let mut known = entry_known(compiler, map, opcode)?;
    let modrm = entry & 3;
    if modrm == 0 {
        // No ModRM: the tail leaves MOD, REG and RM zero.
        for field in ["MOD", "REG", "RM"] {
            known.set_single(field, 0);
        }
    }
    let mut code = compiler.specialize_part1(part1, &mut known)?;
    if code.diverges {
        return Ok(None);
    }
    // Identification tests `EOSZ`/`EASZ` as the opcode's size
    // nonterminals give them, in locals (as `identify.rs`).
    let mut tested = known.clone();
    let mut sizes = Vec::new();
    for (field, local) in [("EOSZ", "id_eosz"), ("EASZ", "id_easz")] {
        if !bin.candidates.iter().any(|c| c.fields.contains_key(field)) {
            continue;
        }
        let sequences: BTreeSet<&Vec<String>> = bin
            .candidates
            .iter()
            .map(|c| if field == "EOSZ" { &c.eosz } else { &c.easz })
            .collect();
        let [sequence] = sequences.into_iter().collect::<Vec<_>>()[..] else {
            return Err(format!("patterns disagree on {field} nonterminals").into());
        };
        let sequence: Vec<&str> = sequence.iter().map(String::as_str).collect();
        let values = ild::size_values(inputs.grammar, &sequence, field)?;
        let (expr, domain) = compiler.specialize_size(&values, &known)?;
        let local = format_ident!("{local}");
        sizes.push((field, quote!(let #local: u8 = #expr;)));
        tested.set(field, domain);
    }
    let mut candidates: Vec<Candidate> = bin
        .candidates
        .iter()
        .filter(|c| {
            c.fields
                .iter()
                .all(|(f, allowed)| tested.admits(f, allowed))
        })
        .cloned()
        .collect();
    if candidates.is_empty() {
        return Ok(None);
    }
    for candidate in &mut candidates {
        candidate
            .fields
            .retain(|field, allowed| !tested.implies(field, allowed));
    }
    let fields: Vec<String> = candidates
        .iter()
        .flat_map(|c| c.fields.keys().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    // The sizes identification still tests.
    let sizes: TokenStream = sizes
        .into_iter()
        .filter(|(field, _)| fields.iter().any(|f| f == field))
        .map(|(_, local)| local)
        .collect();
    let mut arms = Vec::new();
    for candidate in &candidates {
        let mut inside = known.clone();
        for (field, allowed) in &candidate.fields {
            if !matches!(field.as_str(), "EOSZ" | "EASZ") {
                inside.narrow(field, allowed);
            }
        }
        let body = instruction_body(compiler, inputs, candidate.number, &mut inside)?;
        let required: Vec<Option<Allowed>> = fields
            .iter()
            .map(|field| candidate.fields.get(field).cloned())
            .collect();
        arms.push((required, body));
    }
    if fields.is_empty() {
        let [(_, body)] = &arms[..] else {
            return Err(format!("{} instructions match without a test", arms.len()).into());
        };
        code.then(Code {
            tokens: quote!(#sizes #body),
            diverges: true,
        });
        return Ok(Some(code.tokens));
    }
    let keys = fields
        .iter()
        .map(|field| match field.as_str() {
            "EOSZ" => Ok((quote!(id_eosz), 2)),
            "EASZ" => Ok((quote!(id_easz), 2)),
            other => compiler.key(other),
        })
        .collect::<Result<Vec<_>>>()?;
    let matched = emit_match(&keys, &arms, &bail());
    code.then(Code {
        tokens: quote!(#sizes #matched),
        diverges: true,
    });
    Ok(Some(code.tokens))
}

/// Instruction `number`'s pattern nonterminals and operands, then its
/// result; always returns.
fn instruction_body(
    compiler: &mut Compiler<'_, '_>,
    inputs: &Inputs<'_, '_>,
    number: u16,
    known: &mut Known,
) -> Result<TokenStream> {
    let index = usize::from(number)
        .checked_sub(1)
        .ok_or("instruction number 0")?;
    let instruction = inputs
        .instructions
        .get(index)
        .ok_or("instruction number out of range")?;
    let added = inputs
        .added
        .get(index)
        .ok_or("instruction number out of range")?;
    let binbun_xed::pattern::Pattern::Tokens(tokens) = &instruction.pattern else {
        return Err(format!("line {}: `otherwise` instruction", instruction.line).into());
    };
    let mut code = Code::default();
    for nt in super::grammar::conditions(tokens).1 {
        if code.then(compiler.specialize_call(nt, known)?) {
            return Ok(code.tokens);
        }
    }
    let decoded = parse_added(
        instruction.line,
        added.iter().filter(|a| !a.capture),
        inputs.macros,
    )?;
    for operand in instruction.operands.iter().chain(&decoded) {
        if code.then(compiler.specialize_operand(operand, known)?) {
            return Ok(code.tokens);
        }
    }
    let number = lit(number);
    code.then(Code {
        tokens: quote!(return F::finish(s, #number, address, bytes);),
        diverges: true,
    });
    Ok(code.tokens)
}
