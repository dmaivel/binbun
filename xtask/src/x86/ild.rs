//! Instruction-length decoder tables (`generated/ild.rs`).
//!
//! The length decoder is hand-written (`binbun-x86/src/ild.rs`); what
//! it needs per opcode comes from the instruction patterns, as XED's
//! `ild*.py` derive it:
//!
//! - which map each opcode map description names, and how it is reached;
//! - per `(encoding space, map, opcode)`: whether a ModRM byte follows, the
//!   immediate width and any displacement beyond ModRM's, for maps whose
//!   description says `var`.
//!
//! Widths that depend on the effective operand or address size are
//! evaluated here, through the pattern's size nonterminals (`OSZ_NONTERM`,
//! then e.g. `DF64`), for every `(MODE, 66, 67, REX.W)` combination, so the
//! runtime looks up a 24-entry table instead of evaluating nonterminals.
//! Each rule is then flattened to one width per `(MODE, 66, 67, REX.W,
//! ModRM.reg, REX2)` ([`WIDTH_POINTS`]), so that the runtime reads a width
//! with one table lookup.

use std::collections::{BTreeMap, BTreeSet};

use binbun_xed::StateMacros;
use binbun_xed::instructions::Record;
use binbun_xed::maps::{Displacement, Immediate, MapId, ModRm, OpcodeMap, Space};
use binbun_xed::pattern::{self, Pattern, Test};
use proc_macro2::TokenStream;
use quote::quote;

use super::grammar::{self, Grammar};
use super::output;
use crate::Result;
use crate::codegen::{GeneratedFile, XED_NOTICE, count, hex, lit};

/// Number of `(MODE, OSZ, ASZ, REXW)` combinations.
pub const SIZE_POINTS: usize = 3 * 2 * 2 * 2;

/// Number of `(MODE, OSZ, ASZ, REXW, ModRM.reg, REX2)` combinations, at
/// `(size_point * 8 + reg) * 2 + rex2`.
const WIDTH_POINTS: usize = SIZE_POINTS * 8 * 2;

/// Flattened width entries that are not bit counts.
const WIDTH_UNSET: u8 = 0xff;
const WIDTH_ENTER: u8 = 0xfe;
const WIDTH_MAP1_OP78: u8 = 0xfd;

/// ModRM presence of one opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Modrm {
    No,
    Yes,
    /// `MOV` to/from control and debug registers: ModRM is read but its MOD
    /// does not select memory.
    IgnoreMod,
    /// `UD0`: ModRM unless the decoder models the short (pre-Pentium Pro)
    /// encoding.
    Ud0,
}

/// How an immediate or displacement width is found for one opcode.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Width {
    /// No immediate; or for displacements, only ModRM's.
    None,
    /// A fixed width in bits.
    Bits(u8),
    /// One width per `(MODE, OSZ, ASZ, REXW)`.
    Sized([u8; SIZE_POINTS]),
    /// Per `ModRM.reg`; `None` where no instruction has that `reg`.
    ByReg([Option<Box<Width>>; 8]),
    /// Per `MODE`.
    ByMode([Option<Box<Width>>; 3]),
    /// Without and with a REX2 prefix.
    ByRex2([Option<Box<Width>>; 2]),
    /// `ENTER`: 16-bit immediate, then an 8-bit one.
    Enter,
    /// `0F 78`: `EXTRQ`/`INSERTQ` (8-bit then 8-bit immediates) with a `66`
    /// or `F2` prefix, `VMREAD` (none) otherwise.
    Map1Op78,
}

/// What one instruction pattern tells the length decoder.
#[derive(Debug, Clone)]
struct Info<'a> {
    line: u32,
    modrm: Modrm,
    reg: Option<u8>,
    modes: BTreeSet<u64>,
    rex2: Option<u64>,
    imm: Vec<&'a str>,
    disp: Vec<&'a str>,
    eosz: Vec<&'a str>,
    easz: Vec<&'a str>,
}

/// A map in the numbering the runtime uses.
#[derive(Debug)]
pub struct Map<'a> {
    pub space: u8,
    pub id: u8,
    pub description: &'a OpcodeMap<'a>,
}

#[derive(Debug, Default)]
struct Rules {
    imm: Vec<Width>,
    disp: Vec<Width>,
}

/// Each map's packed opcode entries, by `(encoding space, map)`.
pub type OpcodeEntries = BTreeMap<(u8, u8), Vec<u16>>;

pub fn generate<'a>(
    records: &[&Record<'a>],
    grammar: &Grammar<'a>,
    descriptions: &'a [OpcodeMap<'a>],
    macros: &StateMacros<'a>,
) -> Result<(GeneratedFile, OpcodeEntries)> {
    let maps = number_maps(descriptions);
    let setters = Setters {
        imm: grammar
            .setters("IMM_WIDTH")
            .into_iter()
            .filter(|&nt| nt != "ONE")
            .collect(),
        disp: grammar
            .setters("DISP_WIDTH")
            .union(&grammar.setters("BRDISP_WIDTH"))
            .copied()
            .collect(),
        eosz: grammar.setters("EOSZ"),
        easz: grammar.setters("EASZ"),
    };
    let bins = bin_patterns(records, macros, &maps, &setters)?;

    let mut rules = Rules {
        imm: vec![Width::None],
        disp: vec![Width::None],
    };
    // One packed entry per opcode: ModRM in bits 0-1, the immediate rule in
    // bits 2-7, the displacement rule in bits 8-15.
    let mut tables: Vec<(&Map<'_>, Vec<u16>)> = Vec::new();
    for map in &maps {
        let key = |opcode: u8| (map.space, map.id, opcode);
        let infos = |opcode: u8| bins.get(&key(opcode)).map_or(&[][..], Vec::as_slice);
        let mut table = Vec::with_capacity(256);
        for opcode in 0..=255u8 {
            let modrm = match map.description.modrm {
                ModRm::Yes => Modrm::Yes,
                ModRm::No => Modrm::No,
                ModRm::Var => {
                    let list = infos(opcode);
                    if !list.is_empty() {
                        modrm(map, opcode, list)?
                    } else if map.space != 0 && map.id <= 1 {
                        // Unused VEX/EVEX map 0/1 opcodes take legacy map 0/1's
                        // ModRM; with none there either, XED's gap data says no.
                        let legacy = bins
                            .get(&(0, map.id, opcode))
                            .map_or(&[][..], Vec::as_slice);
                        if legacy.is_empty() {
                            Modrm::No
                        } else {
                            modrm(map, opcode, legacy)?
                        }
                    } else {
                        // XED's "undefined", which its scanner treats as present.
                        Modrm::Yes
                    }
                }
            };
            let imm = match (map.description.immediate, map.space, map.id, opcode) {
                (Immediate::Bytes(0), ..) => Width::None,
                (Immediate::Bytes(bytes), ..) => Width::Bits(bytes * 8),
                (Immediate::Var, 0, 0, 0xc8) => Width::Enter,
                (Immediate::Var, 0, 1, 0x78) => Width::Map1Op78,
                (Immediate::Var, ..) => resolve(
                    infos(opcode),
                    &|info| size_rule(grammar, info, &info.imm, "IMM_WIDTH"),
                    false,
                )
                .map_err(|e| {
                    format!(
                        "immediate of space {} map {} opcode {opcode:#04x}: {e}",
                        map.space, map.id
                    )
                })?,
            };
            let disp = match map.description.displacement {
                Displacement::No => Width::None,
                Displacement::Var => resolve(
                    infos(opcode),
                    &|info| size_rule(grammar, info, &info.disp, ""),
                    true,
                )
                .map_err(|e| {
                    format!(
                        "displacement of space {} map {} opcode {opcode:#04x}: {e}",
                        map.space, map.id
                    )
                })?,
            };
            let modrm = match modrm {
                Modrm::No => 0,
                Modrm::Yes => 1,
                Modrm::IgnoreMod => 2,
                Modrm::Ud0 => 3,
            };
            let (imm, disp) = (intern(&mut rules.imm, imm), intern(&mut rules.disp, disp));
            if imm >= 64 || disp >= 256 {
                return Err("too many immediate or displacement rules to pack".into());
            }
            table.push(modrm | u16::try_from(imm << 2 | disp << 8)?);
        }
        tables.push((map, table));
    }

    let entries: BTreeMap<(u8, u8), Vec<u16>> = tables
        .iter()
        .map(|(map, entries)| ((map.space, map.id), entries.clone()))
        .collect();
    let tokens = emit(&maps, &tables, &rules)?;
    let file = GeneratedFile {
        path: output("ild"),
        notice: XED_NOTICE,
        docs: vec![
            "Opcode maps and per-opcode length rules for the instruction-length decoder."
                .to_owned(),
        ],
        tokens,
    };
    Ok((file, entries))
}

struct Setters<'a> {
    imm: BTreeSet<&'a str>,
    disp: BTreeSet<&'a str>,
    eosz: BTreeSet<&'a str>,
    easz: BTreeSet<&'a str>,
}

/// Every instruction pattern's [`Info`], by `(space, map, opcode)`. A form
/// with a `REG[lo-hi]` range counts once per `reg`.
fn bin_patterns<'a>(
    records: &[&Record<'a>],
    macros: &StateMacros<'a>,
    maps: &[Map<'_>],
    setters: &Setters<'a>,
) -> Result<BTreeMap<(u8, u8, u8), Vec<Info<'a>>>> {
    let mut bins: BTreeMap<(u8, u8, u8), Vec<Info<'a>>> = BTreeMap::new();
    for record in records {
        for form in &record.forms {
            let regs: Vec<Option<u8>> = match pattern::reg_range(form.line, form.pattern)? {
                Some(range) => range.map(Some).collect(),
                None => vec![None],
            };
            for reg in regs {
                let parsed = pattern::parse_with_reg(form.line, form.pattern, macros, reg)?;
                let (space, map, opcodes) = locate(form.line, form.pattern, &parsed, maps)?;
                let info = analyse(form.line, form.pattern, &parsed, setters);
                for opcode in opcodes {
                    bins.entry((space, map, opcode))
                        .or_default()
                        .push(info.clone());
                }
            }
        }
    }
    Ok(bins)
}

/// Map descriptions with the runtime's `(space, id)`: the space is XED's
/// VEXVALID; a named legacy map (3DNow!) takes the next free legacy id.
/// Ordered as XED tries them: longest search pattern first.
pub fn number_maps<'a>(descriptions: &'a [OpcodeMap<'a>]) -> Vec<Map<'a>> {
    let space_of = |space: Space| match space {
        Space::Legacy => 0,
        Space::Vex => 1,
        Space::Evex => 2,
        Space::Xop => 3,
    };
    let mut next_legacy = descriptions
        .iter()
        .filter_map(|d| match (d.space, d.id) {
            (Space::Legacy, MapId::Number(n)) => Some(n + 1),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    let mut maps: Vec<Map<'a>> = descriptions
        .iter()
        .map(|description| {
            let id = match description.id {
                MapId::Number(n) => n,
                MapId::Named(_) => {
                    next_legacy += 1;
                    next_legacy - 1
                }
            };
            Map {
                space: space_of(description.space),
                id,
                description,
            }
        })
        .collect();
    maps.sort_by_key(|map| std::cmp::Reverse(map.description.pattern.len()));
    maps
}

/// The `(space, map, opcodes)` of a pattern (XED's `pattern_t._get_map_opcode`):
/// the first map of the pattern's space whose search pattern occurs in the
/// pattern text, and the word at the map's opcode position. A binary opcode
/// shorter than 8 bits covers every value of its missing low bits when the
/// pattern captures them as `RM[rrr]` or `REG[rrr]`.
pub fn locate(
    line: u32,
    text: &str,
    parsed: &Pattern<'_>,
    maps: &[Map<'_>],
) -> Result<(u8, u8, Vec<u8>)> {
    let Pattern::Tokens(tokens) = parsed else {
        return Err(format!("line {line}: `otherwise` is not an instruction pattern").into());
    };
    let (conditions, _) = grammar::conditions(tokens);
    let space = conditions
        .iter()
        .find(|c| c.field == "VEXVALID" && c.test == Test::Eq)
        .map_or(0, |c| c.value);
    let map = maps
        .iter()
        .find(|m| {
            u64::from(m.space) == space
                && (m.description.pattern.is_empty() || text.contains(m.description.pattern))
        })
        .ok_or_else(|| format!("line {line}: no opcode map matches `{text}`"))?;
    let words: Vec<&str> = text.split_whitespace().collect();
    let position = map.description.opcode_position;
    let word = if position < 0 {
        words
            .len()
            .checked_sub(position.unsigned_abs().into())
            .and_then(|i| words.get(i))
    } else {
        words.get(usize::try_from(position)?)
    }
    .ok_or_else(|| format!("line {line}: no opcode at position {position}"))?;
    let (value, missing) = if let Some(binary) = word.strip_prefix("0b") {
        let digits: String = binary.chars().filter(|&c| c != '_').collect();
        let missing = 8usize
            .checked_sub(digits.len())
            .ok_or_else(|| format!("line {line}: opcode `{word}` too long"))?;
        (u8::from_str_radix(&digits, 2)? << missing, missing)
    } else if let Some(hex) = word.strip_prefix("0x") {
        (u8::from_str_radix(hex, 16)?, 0)
    } else {
        (
            word.parse::<u8>()
                .map_err(|_| format!("line {line}: opcode `{word}` is not a number"))?,
            0,
        )
    };
    let opcodes = if missing > 0 && (text.contains("RM[rrr]") || text.contains("REG[rrr]")) {
        (0..1u8 << missing).map(|low| value | low).collect()
    } else {
        vec![value]
    };
    Ok((map.space, map.id, opcodes))
}

fn analyse<'a>(line: u32, text: &str, parsed: &Pattern<'a>, setters: &Setters<'a>) -> Info<'a> {
    let modrm = if text.contains("MOD[")
        && !text.contains("VMODRM")
        && !text.contains("MODRM()")
        && !text.contains("MOD=3")
    {
        Modrm::IgnoreMod
    } else if text.contains("MODRM()") || text.contains("MOD[") {
        Modrm::Yes
    } else {
        Modrm::No
    };
    let tokens = match parsed {
        Pattern::Tokens(tokens) => tokens.as_slice(),
        Pattern::Otherwise => &[],
    };
    let (conditions, _) = grammar::conditions(tokens);
    let reg = tokens.iter().find_map(|token| {
        if let pattern::Token::Capture { field: "REG", bits } = token {
            grammar::literal(bits).and_then(|v| u8::try_from(v).ok())
        } else {
            None
        }
    });
    let all_modes: BTreeSet<u64> = (0..3).collect();
    let modes = conditions
        .iter()
        .find(|c| c.field == "MODE")
        .map_or(all_modes.clone(), |c| {
            all_modes.iter().copied().filter(|&m| c.holds(m)).collect()
        });
    let rex2 = text.split_whitespace().find_map(|word| match word {
        "rex2_refining_prefix" => Some(1),
        "norex2_prefix" => Some(0),
        _ => None,
    });
    let mut imm_set = setters.imm.clone();
    imm_set.insert("UIMM8_1");
    Info {
        line,
        modrm,
        reg,
        modes,
        rex2,
        imm: sequence(text, &imm_set, None),
        disp: sequence(text, &setters.disp, None),
        eosz: sequence(text, &setters.eosz, Some("OSZ_NONTERM")),
        easz: sequence(text, &setters.easz, Some("ASZ_NONTERM")),
    }
}

/// ModRM presence for one opcode: every pattern must agree, except `0F FF`
/// (`UD0`, whose length differs between processors).
fn modrm(map: &Map<'_>, opcode: u8, infos: &[Info<'_>]) -> Result<Modrm> {
    let Some(first) = infos.first() else {
        return Ok(Modrm::Yes);
    };
    if infos.iter().all(|info| info.modrm == first.modrm) {
        return Ok(first.modrm);
    }
    if map.id == 1 && opcode == 0xff {
        return Ok(Modrm::Ud0);
    }
    Err(format!(
        "ModRM presence conflicts in space {} map {} opcode {opcode:#04x}",
        map.space, map.id
    )
    .into())
}

/// The width rule of one pattern: from its single width nonterminal,
/// evaluated after its size nonterminals at every size point.
fn size_rule(
    grammar: &Grammar<'_>,
    info: &Info<'_>,
    sequence: &[&str],
    field: &str,
) -> Result<Width> {
    let sequence: Vec<&str> = sequence
        .iter()
        .copied()
        .filter(|&nt| nt != "UIMM8_1")
        .collect();
    let nt = match sequence.as_slice() {
        [] => return Ok(Width::None),
        [nt] => *nt,
        _ => {
            return Err(format!(
                "line {}: several width nonterminals {sequence:?}",
                info.line
            )
            .into());
        }
    };
    let mut widths = [0u8; SIZE_POINTS];
    for (point, width) in widths.iter_mut().enumerate() {
        let mut env = size_point(point);
        let operand_size = overlay(grammar, &info.eosz, &env, "EOSZ")?;
        let address_size = overlay(grammar, &info.easz, &env, "EASZ")?;
        env.extend(operand_size.map(|v| ("EOSZ", v)));
        env.extend(address_size.map(|v| ("EASZ", v)));
        let rule = grammar.evaluate(nt, &env)?;
        let bits = rule.and_then(|rule| {
            if field.is_empty() {
                rule.binds("DISP_WIDTH")
                    .or_else(|| rule.binds("BRDISP_WIDTH"))
            } else {
                rule.binds(field)
            }
        });
        *width = u8::try_from(bits.ok_or_else(|| {
            format!(
                "line {}: {nt} gives no width at size point {point}",
                info.line
            )
        })?)?;
    }
    Ok(if widths.iter().all(|&w| w == widths[0]) {
        Width::Bits(widths[0])
    } else {
        Width::Sized(widths)
    })
}

/// The value the last nonterminal of `sequence` that binds `field` at `env`
/// gives it (XED's `gen_nt_seq_lookup`: later ones override earlier ones).
pub fn overlay(
    grammar: &Grammar<'_>,
    sequence: &[&str],
    env: &BTreeMap<&str, u64>,
    field: &str,
) -> Result<Option<u64>> {
    let mut value = None;
    for nt in sequence {
        if let Some(bound) = grammar
            .evaluate(nt, env)?
            .and_then(|rule| rule.binds(field))
        {
            value = Some(bound);
        }
    }
    Ok(value)
}

/// The fields of size point `point`: `MODE`, `OSZ`, `ASZ` and `REXW`, in
/// the runtime's order `((MODE * 2 + OSZ) * 2 + ASZ) * 2 + REXW`.
pub fn size_point(point: usize) -> BTreeMap<&'static str, u64> {
    let (mode, osz, asz, rexw) = (point / 8, point / 4 % 2, point / 2 % 2, point % 2);
    [("MODE", mode), ("OSZ", osz), ("ASZ", asz), ("REXW", rexw)]
        .into_iter()
        .map(|(k, v)| (k, v as u64))
        .collect()
}

/// `field` (`EOSZ` or `EASZ`) after the size nonterminals `sequence`, at
/// every size point.
pub fn size_values(
    grammar: &Grammar<'_>,
    sequence: &[&str],
    field: &str,
) -> Result<[u8; SIZE_POINTS]> {
    let mut values = [0u8; SIZE_POINTS];
    for (point, value) in values.iter_mut().enumerate() {
        let bound = overlay(grammar, sequence, &size_point(point), field)?
            .ok_or_else(|| format!("{sequence:?} gives no {field} at size point {point}"))?;
        *value = u8::try_from(bound)?;
    }
    Ok(values)
}

/// The nonterminals of `set` in a pattern's words, after `implied`.
pub fn sequence<'a>(text: &str, set: &BTreeSet<&'a str>, implied: Option<&'a str>) -> Vec<&'a str> {
    implied
        .into_iter()
        .chain(
            text.split_whitespace()
                .filter_map(|w| set.get(w.trim_end_matches("()")).copied()),
        )
        .collect()
}

/// One width for an opcode's patterns: their common rule, else split by
/// `ModRM.reg`, then (displacements only) by mode or REX2, as XED does.
fn resolve(
    infos: &[Info<'_>],
    rule: &dyn Fn(&Info<'_>) -> Result<Width>,
    more: bool,
) -> Result<Width> {
    let common = |subset: &[&Info<'_>]| -> Result<Option<Width>> {
        let mut widths = subset.iter().map(|info| rule(info));
        let Some(first) = widths.next().transpose()? else {
            return Ok(None);
        };
        for width in widths {
            if width? != first {
                return Err("conflict".into());
            }
        }
        Ok(Some(first))
    };
    let all: Vec<&Info<'_>> = infos.iter().collect();
    if let Ok(width) = common(&all) {
        return Ok(width.unwrap_or(Width::None));
    }
    let split = |key: &dyn Fn(&Info<'_>, u64) -> bool,
                 values: u64|
     -> Option<Vec<Option<Box<Width>>>> {
        let groups = (0..values)
            .map(|value| {
                let subset: Vec<&Info<'_>> = infos.iter().filter(|info| key(info, value)).collect();
                common(&subset).ok().map(|width| width.map(Box::new))
            })
            .collect::<Option<Vec<_>>>()?;
        // XED gives up when no value has any pattern.
        groups.iter().any(Option::is_some).then_some(groups)
    };
    if let Some(by_reg) = split(&|info, reg| info.reg == u8::try_from(reg).ok(), 8) {
        return Ok(Width::ByReg(by_reg.try_into().map_err(|_| "eight")?));
    }
    if more {
        if let Some(by_mode) = split(&|info, mode| info.modes.contains(&mode), 3) {
            return Ok(Width::ByMode(by_mode.try_into().map_err(|_| "three")?));
        }
        if infos.iter().all(|info| info.rex2.is_some())
            && let Some(by_rex2) = split(&|info, rex2| info.rex2 == Some(rex2), 2)
            && by_rex2.iter().all(Option::is_some)
        {
            return Ok(Width::ByRex2(by_rex2.try_into().map_err(|_| "two")?));
        }
    }
    let lines: Vec<u32> = infos.iter().map(|info| info.line).collect();
    Err(format!("patterns on lines {lines:?} disagree").into())
}

/// Index of `width` in `rules`, adding it if new.
fn intern(rules: &mut Vec<Width>, width: Width) -> usize {
    rules.iter().position(|w| *w == width).unwrap_or_else(|| {
        rules.push(width);
        rules.len() - 1
    })
}

fn emit(maps: &[Map<'_>], tables: &[(&Map<'_>, Vec<u16>)], rules: &Rules) -> Result<TokenStream> {
    let mut by_id: Vec<&(&Map<'_>, Vec<u16>)> = tables.iter().collect();
    by_id.sort_by_key(|(map, _)| (map.space, map.id));
    // TABLE_INDEX[space * 32 + map] is the map's index in OPCODES, or 0 for
    // the empty first table. Map 31 must not exist: out-of-range map
    // numbers are masked to it.
    let mut index = [0u8; 128];
    for (i, (map, _)) in by_id.iter().enumerate() {
        if map.id >= 31 {
            return Err(format!("map number {} above 30", map.id).into());
        }
        let slot = usize::from(map.space) * 32 + usize::from(map.id);
        *index.get_mut(slot).ok_or("encoding space above 3")? = u8::try_from(i + 1)?;
    }
    let index = index.iter().map(|&i| lit(i));
    let table_count = count(by_id.len() + 1);
    let tables = by_id.iter().map(|(_, entries)| {
        let entries = entries.iter().map(|&e| lit(e));
        quote!([#(#entries),*])
    });
    let legacy_escapes = maps
        .iter()
        .filter(|m| m.space == 0 && m.description.escape.is_some())
        .map(|map| {
            let id = lit(map.id);
            let second = map.description.opcode.map_or_else(
                || quote!(None),
                |byte| {
                    let byte = hex(byte);
                    quote!(Some(#byte))
                },
            );
            let trailing = map.description.opcode_position < 0;
            quote!(LegacyMap { second: #second, map: #id, trailing_opcode: #trailing })
        });
    let escape_count = count(
        maps.iter()
            .filter(|m| m.space == 0 && m.description.escape.is_some())
            .count(),
    );

    let flat_tables = |rules: &[Width]| -> Vec<TokenStream> {
        rules
            .iter()
            .map(|rule| {
                let widths = flatten(rule).map(lit);
                quote!([#(#widths),*])
            })
            .collect()
    };
    let (imm_count, disp_count) = (count(rules.imm.len()), count(rules.disp.len()));
    let imm_widths = flat_tables(&rules.imm);
    let disp_widths = flat_tables(&rules.disp);
    let points = count(WIDTH_POINTS);
    let (unset, enter, map1_op78) = (hex(WIDTH_UNSET), hex(WIDTH_ENTER), hex(WIDTH_MAP1_OP78));

    Ok(quote! {
        use crate::ild::LegacyMap;

        /// The index in [`OPCODES`] of map `map` of encoding space `space`
        /// (XED's VEXVALID: 0 legacy, 1 VEX, 2 EVEX, 3 XOP), at
        /// `space * 32 + map`; 0 (an empty table) where no such map exists,
        /// including at map 31, where larger map numbers are masked to.
        pub static TABLE_INDEX: [u8; 128] = [#(#index),*];

        /// The opcodes of each map, after an empty table. Each entry packs
        /// ModRM presence (bits 0-1: none, present, present with MOD
        /// ignored, `UD0`), the immediate rule (bits 2-7, into
        /// `IMM_WIDTHS`) and the displacement rule (bits 8-15, into
        /// `DISP_WIDTHS`).
        pub static OPCODES: [[u16; 256]; #table_count] = [[0; 256], #(#tables),*];

        /// Legacy maps reached through `0F`, most specific first.
        pub static LEGACY_ESCAPES: [LegacyMap; #escape_count] = [#(#legacy_escapes),*];

        /// A width entry that leaves the width as it is.
        pub const WIDTH_UNSET: u8 = #unset;
        /// The immediate entry of `ENTER`: a 16-bit, then an 8-bit
        /// immediate.
        pub const WIDTH_ENTER: u8 = #enter;
        /// The immediate entry of `0F 78`: two 8-bit immediates
        /// (`EXTRQ`, `INSERTQ`) with a `66` or `F2` prefix, else none
        /// (`VMREAD`).
        pub const WIDTH_MAP1_OP78: u8 = #map1_op78;

        /// Immediate widths in bits of each rule, by
        /// `(size point * 8 + ModRM.reg) * 2 + REX2`, where the size point is
        /// `((MODE * 2 + OSZ) * 2 + ASZ) * 2 + REXW`.
        pub static IMM_WIDTHS: [[u8; #points]; #imm_count] = [#(#imm_widths),*];

        /// Displacement widths in bits of each rule, indexed as
        /// [`IMM_WIDTHS`].
        pub static DISP_WIDTHS: [[u8; #points]; #disp_count] = [#(#disp_widths),*];
    })
}

/// `rule`'s width at every `(size point, ModRM.reg, REX2)`: bits, or one of
/// the `WIDTH_*` markers.
fn flatten(rule: &Width) -> [u8; WIDTH_POINTS] {
    std::array::from_fn(|point| {
        let (size_point, reg, rex2) = (point / 16, point / 2 % 8, point % 2);
        width_at(rule, size_point, reg, rex2)
    })
}

/// `rule`'s width at one point (the runtime's former rule interpreter).
fn width_at(rule: &Width, size_point: usize, reg: usize, rex2: usize) -> u8 {
    let child = |children: &[Option<Box<Width>>], index: usize| {
        children
            .get(index)
            .and_then(Option::as_deref)
            .map_or(WIDTH_UNSET, |c| width_at(c, size_point, reg, rex2))
    };
    match rule {
        Width::None => WIDTH_UNSET,
        Width::Bits(bits) => *bits,
        Width::Sized(table) => table.get(size_point).copied().unwrap_or(WIDTH_UNSET),
        Width::ByReg(children) => child(children, reg),
        // The size point's mode: points are `MODE * 8 + ...`.
        Width::ByMode(children) => child(children, size_point / 8),
        Width::ByRex2(children) => child(children, rex2),
        Width::Enter => WIDTH_ENTER,
        Width::Map1Op78 => WIDTH_MAP1_OP78,
    }
}
