//! Parses the vendored XED datafiles and compares against XED's own generator.
//!
//! Expected values come from the C XED generated from the same inputs (XED
//! commit 0bcb623, v2026.08.23; see `third_party/xed/VERSION`), e.g.
//! `obj/xed-iclass-enum.h`, counting members other than `INVALID` and `LAST`.
//! Re-derive them whenever `scripts/update-xed.sh` changes the vendored files.

use std::collections::BTreeSet;

use binbun_xed::pattern::{self, Pattern, Token};
use binbun_xed::{
    Datafile, StateMacros, fields, flags, instructions, maps, nonterminals, operands, tables,
};

macro_rules! vendored {
    ($file:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../third_party/xed/",
            $file
        ))
    };
}

#[test]
fn every_flags_field_and_map_description_parses() {
    let instruction_file = Datafile::new(vendored!("all-dec-instructions.txt"));
    let map_file = Datafile::new(vendored!("all-map-descriptions.txt"));
    let tables = instructions::parse(&instruction_file).unwrap();
    for record in tables.iter().flat_map(|table| &table.records) {
        if let Some(text) = record.flags {
            flags::parse(record.line, text).unwrap();
        }
    }

    let maps = maps::parse(&map_file).unwrap();
    let legacy: Vec<_> = maps
        .iter()
        .filter(|map| map.space == maps::Space::Legacy)
        .map(|map| (map.escape, map.opcode))
        .collect();
    assert_eq!(
        legacy,
        [
            (None, None),
            (Some(0x0f), None),
            (Some(0x0f), Some(0x38)),
            (Some(0x0f), Some(0x3a)),
            (Some(0x0f), Some(0x0f)),
        ]
    );
}

#[test]
fn instruction_records_match_xed_generator() {
    let file = Datafile::new(vendored!("all-dec-instructions.txt"));
    let tables = instructions::parse(&file).unwrap();

    let names: Vec<&str> = tables.iter().map(|table| table.name).collect();
    assert_eq!(
        names,
        [
            "INSTRUCTIONS",
            "AVX_INSTRUCTIONS",
            "XOP_INSTRUCTIONS",
            "EVEX_INSTRUCTIONS"
        ]
    );

    let records: usize = tables.iter().map(|table| table.records.len()).sum();
    assert_eq!(records, 9141, "every `{{ … }}` record in the file");

    let selected: Vec<_> = tables
        .iter()
        .flat_map(instructions::Table::selected)
        .collect();
    let distinct = |field: for<'r> fn(&'r instructions::Record<'r>) -> &'r str| -> usize {
        selected
            .iter()
            .map(|record| field(record))
            .collect::<BTreeSet<_>>()
            .len()
    };
    // xed-iclass-enum.h has 1995; NOP2..NOP9 come only from the encoder's xed-nops.txt.
    assert_eq!(distinct(|r| r.iclass), 1995 - 8, "xed-iclass-enum.h");
    assert_eq!(distinct(|r| r.extension), 109, "xed-extension-enum.h");
    assert_eq!(distinct(|r| r.category), 113, "xed-category-enum.h");

    // XED_MAX_INST_TABLE_NODES (xed-init-inst-table.h) counts one entry per
    // form after deletion, version selection and `REG[lo-hi]` expansion, plus
    // the INVALID entry.
    let mut forms = 0;
    for form in selected.iter().flat_map(|record| &record.forms) {
        forms += pattern::reg_range(form.line, form.pattern)
            .unwrap()
            .map_or(1, Iterator::count);
    }
    assert_eq!(1 + forms, 11_019, "XED_MAX_INST_TABLE_NODES");
}

#[test]
fn every_instruction_pattern_parses_and_names_known_fields() {
    let instruction_file = Datafile::new(vendored!("all-dec-instructions.txt"));
    let state_file = Datafile::new(vendored!("all-state.txt"));
    let field_file = Datafile::new(vendored!("all-fields.txt"));
    let tables = instructions::parse(&instruction_file).unwrap();
    let macros = StateMacros::parse(&state_file).unwrap();
    let fields = fields::parse(&field_file).unwrap();
    assert_eq!(fields.len(), 144);
    let known: BTreeSet<&str> = fields.iter().map(|field| field.name).collect();

    let mut unknown = BTreeSet::new();
    for form in tables
        .iter()
        .flat_map(instructions::Table::selected)
        .flat_map(|record| &record.forms)
    {
        let reg_values = pattern::reg_range(form.line, form.pattern).unwrap();
        let instances: Vec<Option<u8>> = match reg_values {
            Some(range) => range.map(Some).collect(),
            None => vec![None],
        };
        for reg in instances {
            let Pattern::Tokens(tokens) =
                pattern::parse_with_reg(form.line, form.pattern, &macros, reg).unwrap()
            else {
                panic!("line {}: `otherwise` in an instruction pattern", form.line);
            };
            for token in &tokens {
                let field = match token {
                    Token::Capture { field, .. } => field,
                    Token::Constraint(constraint) => &constraint.field,
                    Token::Bits(_) | Token::Nonterminal(_) => continue,
                };
                if !known.contains(field) {
                    unknown.insert(*field);
                }
            }
        }
    }
    assert!(
        unknown.is_empty(),
        "patterns name fields absent from all-fields.txt: {unknown:?}"
    );
}

#[test]
fn nonterminals_match_xed_generator_and_resolve() {
    let state_file = Datafile::new(vendored!("all-state.txt"));
    let pattern_file = Datafile::new(vendored!("all-dec-patterns.txt"));
    let spine_file = Datafile::new(vendored!("all-dec-spine.txt"));
    let instruction_file = Datafile::new(vendored!("all-dec-instructions.txt"));
    let macros = StateMacros::parse(&state_file).unwrap();
    let mut all = nonterminals::parse(&pattern_file, &macros).unwrap();
    all.extend(nonterminals::parse(&spine_file, &macros).unwrap());
    let tables = instructions::parse(&instruction_file).unwrap();

    // xed-nonterminal-enum.h names every nonterminal and instruction table,
    // upper-cased (`rFLAGS` is `XED_NONTERMINAL_RFLAGS`).
    let defined: BTreeSet<&str> = all
        .iter()
        .map(|nt| nt.name)
        .chain(tables.iter().map(|table| table.name))
        .collect();
    let upper: BTreeSet<String> = defined.iter().map(|name| name.to_uppercase()).collect();
    assert_eq!(
        (defined.len(), upper.len()),
        (269, 269),
        "xed-nonterminal-enum.h"
    );

    // Every nonterminal a rule or an instruction pattern refers to is defined.
    let mut form_patterns: Vec<Pattern<'_>> = Vec::new();
    for form in tables
        .iter()
        .flat_map(instructions::Table::selected)
        .flat_map(|record| &record.forms)
    {
        let reg = pattern::reg_range(form.line, form.pattern)
            .unwrap()
            .map(|range| *range.start());
        form_patterns.push(pattern::parse_with_reg(form.line, form.pattern, &macros, reg).unwrap());
    }
    let rule_patterns = all
        .iter()
        .flat_map(|nt| &nt.rules)
        .map(|rule| &rule.pattern);
    let referenced = rule_patterns
        .chain(&form_patterns)
        .filter_map(|pattern| match pattern {
            Pattern::Tokens(tokens) => Some(tokens.iter()),
            Pattern::Otherwise => None,
        });
    let mut missing = BTreeSet::new();
    for token in referenced.flatten() {
        if let Token::Nonterminal(name) = token
            && !defined.contains(name)
        {
            missing.insert(*name);
        }
    }
    assert!(missing.is_empty(), "undefined nonterminals: {missing:?}");
}

#[test]
fn metadata_tables_match_xed_generator() {
    let register_file = Datafile::new(vendored!("all-registers.txt"));
    let width_file = Datafile::new(vendored!("all-widths.txt"));
    let element_file = Datafile::new(vendored!("all-element-types.txt"));
    let extra_file = Datafile::new(vendored!("all-extra-widths.txt"));

    let rows = tables::registers(&register_file).unwrap();
    assert_eq!(
        tables::merge_registers(&rows).len(),
        1 + 365,
        "INVALID + xed-reg-enum.h"
    );

    let widths = tables::widths(&width_file).unwrap();
    let width_names: BTreeSet<String> = widths.iter().map(|w| w.name.to_uppercase()).collect();
    assert_eq!(
        width_names.len(),
        1 + 138,
        "INVALID + xed-operand-width-enum.h"
    );

    let elements = tables::element_types(&element_file).unwrap();
    let element_names: BTreeSet<&str> = elements.iter().map(|e| e.name).collect();
    assert_eq!(element_names.len(), 38, "xed-operand-element-xtype-enum.h");

    // Every extra width names a known width code. (Register rows are not
    // checked: XED's data still lists `X87TOP`, which no register row defines.)
    for extra in tables::extra_widths(&extra_file).unwrap() {
        assert!(
            width_names.contains(&extra.width.to_uppercase()),
            "line {}",
            extra.line
        );
    }
}

#[test]
fn every_operand_list_parses_and_names_known_entities() {
    let state_file = Datafile::new(vendored!("all-state.txt"));
    let instruction_file = Datafile::new(vendored!("all-dec-instructions.txt"));
    let pattern_file = Datafile::new(vendored!("all-dec-patterns.txt"));
    let register_file = Datafile::new(vendored!("all-registers.txt"));
    let width_file = Datafile::new(vendored!("all-widths.txt"));
    let element_file = Datafile::new(vendored!("all-element-types.txt"));
    let macros = StateMacros::parse(&state_file).unwrap();
    let tables_ = instructions::parse(&instruction_file).unwrap();
    let rules = nonterminals::parse(&pattern_file, &macros).unwrap();

    let registers: BTreeSet<String> = tables::registers(&register_file)
        .unwrap()
        .iter()
        .map(|r| format!("XED_REG_{}", r.name.to_uppercase()))
        .collect();
    let widths: BTreeSet<String> = tables::widths(&width_file)
        .unwrap()
        .iter()
        .map(|w| w.name.to_uppercase())
        .collect();
    let elements: BTreeSet<&str> = tables::element_types(&element_file)
        .unwrap()
        .iter()
        .map(|e| e.name)
        .collect();
    let lookups: BTreeSet<&str> = rules.iter().map(|nt| nt.name).collect();

    let lists = tables_
        .iter()
        .flat_map(instructions::Table::selected)
        .flat_map(|record| &record.forms)
        .map(|form| (form.line, form.operands))
        .chain(
            rules
                .iter()
                .flat_map(|nt| &nt.rules)
                .map(|rule| (rule.line, rule.bindings)),
        );
    let mut unknown = BTreeSet::new();
    for (line, text) in lists {
        for word in operands::parse(line, text, &macros).unwrap() {
            let operands::Word::Operand(operand) = word else {
                continue;
            };
            if let operands::Value::Register(name) = operand.value
                && !registers.contains(name)
            {
                unknown.insert(format!("register {name}"));
            }
            if let operands::Value::Lookup(name) = operand.value
                && !lookups.contains(name)
            {
                unknown.insert(format!("nonterminal {name}"));
            }
            if let Some(width) = operand.width
                && !widths.contains(&width.to_uppercase())
            {
                unknown.insert(format!("width {width}"));
            }
            if let Some(element) = operand.element_type
                && !elements.contains(element)
            {
                unknown.insert(format!("element type {element}"));
            }
        }
    }
    assert!(unknown.is_empty(), "unknown names: {unknown:?}");
}
