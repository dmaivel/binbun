//! Generation of `binbun-x86` tables from XED's datafiles.

mod dynamic;
mod enums;
mod fast;
mod forms;
mod grammar;
mod handlers;
mod identify;
mod ild;
mod lift;
mod metadata;
mod mnemonic;
mod operands;
mod register;
mod state;

use std::path::Path;

use binbun_xed::{Datafile, StateMacros, fields, instructions, maps, nonterminals, tables};

use crate::Result;
use crate::codegen::GeneratedFile;

/// Directory of the generated modules, relative to the workspace root.
const OUTPUT: &str = "crates/binbun-x86/src/generated";

/// Parses the vendored XED datafiles and generates every x86 module.
pub fn generate(root: &Path) -> Result<Vec<GeneratedFile>> {
    let read = |name: &str| -> Result<String> {
        let path = root.join("third_party/xed").join(name);
        std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()).into())
    };
    let register_text = read("all-registers.txt")?;
    let instruction_text = read("all-dec-instructions.txt")?;
    let pattern_text = read("all-dec-patterns.txt")?;
    let state_text = read("all-state.txt")?;
    let map_text = read("all-map-descriptions.txt")?;
    let field_text = read("all-fields.txt")?;
    let spine_text = read("all-dec-spine.txt")?;
    let width_text = read("all-widths.txt")?;
    let extra_width_text = read("all-extra-widths.txt")?;
    let element_type_text = read("all-element-types.txt")?;
    let conversion_text = read("all-conversion-table.txt")?;
    let cpuid_text = read("all-cpuid.txt")?;

    let register_file = Datafile::new(&register_text);
    let instruction_file = Datafile::new(&instruction_text);
    let pattern_file = Datafile::new(&pattern_text);
    let state_file = Datafile::new(&state_text);
    let map_file = Datafile::new(&map_text);
    let field_file = Datafile::new(&field_text);
    let spine_file = Datafile::new(&spine_text);
    let width_file = Datafile::new(&width_text);
    let extra_width_file = Datafile::new(&extra_width_text);
    let element_type_file = Datafile::new(&element_type_text);
    let conversion_file = Datafile::new(&conversion_text);
    let cpuid_file = Datafile::new(&cpuid_text);

    let macros = StateMacros::parse(&state_file)?;
    let register_rows = tables::registers(&register_file)?;
    let widths = tables::widths(&width_file)?;
    let extra_widths = tables::extra_widths(&extra_width_file)?;
    let element_types = tables::element_types(&element_type_file)?;
    let conversions = operands::conversion_tables(&conversion_file)?;
    let instruction_tables = instructions::parse(&instruction_file)?;
    let records: Vec<&instructions::Record<'_>> = instruction_tables
        .iter()
        .flat_map(instructions::Table::selected)
        .collect();
    let nonterminals = nonterminals::parse(&pattern_file, &macros)?;
    let grammar = grammar::Grammar::new(&nonterminals, &macros)?;
    let opcode_maps = maps::parse(&map_file)?;
    let field_list = fields::parse(&field_file)?;
    let instruction_list = forms::collect(&records, &macros, &field_list)?;
    let numbered_maps = ild::number_maps(&opcode_maps);
    let state_fields = state::fields(&field_list, &grammar.largest_constants())?;
    let merged_registers = tables::merge_registers(&register_rows);
    let spine_nonterminals = nonterminals::parse(&spine_file, &macros)?;
    let spine: Vec<&str> = spine_nonterminals
        .iter()
        .find(|nt| nt.name == "ISA")
        .and_then(|nt| nt.rules.first())
        .and_then(|rule| match &rule.pattern {
            binbun_xed::pattern::Pattern::Tokens(tokens) => Some(grammar::conditions(tokens).1),
            binbun_xed::pattern::Pattern::Otherwise => None,
        })
        .ok_or("all-dec-spine.txt has no ISA rule")?;

    let (ild_file, entries) = ild::generate(&records, &grammar, &opcode_maps, &macros)?;
    let (identify_file, bins) =
        identify::generate(&instruction_list, &grammar, &numbered_maps, &field_list)?;
    let added = instruction_list
        .iter()
        .map(|instruction| operands::added(instruction, &field_list))
        .collect::<Result<Vec<_>>>()?;
    let register_names = register::names(&merged_registers);
    let (dynamic_file, chains) = dynamic::generate(
        &instruction_list,
        &added,
        &macros,
        &grammar,
        &spine,
        &state_fields,
        &field_list,
        &register_names,
    )?;
    let (flag_file, flag_rules) = metadata::flags(&instruction_list)?;
    let (flow_file, flows) = metadata::flow(&instruction_list)?;
    let fast_file = fast::generate(
        &mut dynamic::Compiler::new(&grammar, &state_fields, &field_list, &register_names),
        &fast::Inputs {
            spine: &spine,
            entries: &entries,
            bins: &bins,
            instructions: &instruction_list,
            added: &added,
            macros: &macros,
            grammar: &grammar,
        },
    )?;
    let (operand_file, operand_lists) = operands::generate(
        &instruction_list,
        &added,
        &field_list,
        &macros,
        &widths,
        &extra_widths,
        &element_types,
        &conversions,
    )?;
    let mut files = vec![
        register::generate(&merged_registers)?,
        mnemonic::generate(&records)?,
        forms::generate(&instruction_list, &operand_lists, &flag_rules, &flows)?,
        flag_file,
        flow_file,
        metadata::cpuid(&instruction_list, &cpuid_file)?,
        operand_file,
        state::generate(&state_fields, &field_list)?,
        handlers::generate(&entries, &bins, &chains)?,
        ild_file,
        identify_file,
        dynamic_file,
        fast_file,
    ];
    files.extend(lift::generate(
        root,
        &instruction_list,
        &added,
        &field_list,
        &macros,
        &merged_registers
            .iter()
            .filter(|r| r.class.eq_ignore_ascii_case("gpr"))
            .map(|r| {
                (
                    r.name.to_ascii_lowercase(),
                    r.width64.or(r.width).unwrap_or(64),
                )
            })
            .collect(),
    )?);
    Ok(files)
}

/// Path of the generated module `name`.
fn output(name: &str) -> std::path::PathBuf {
    Path::new(OUTPUT).join(format!("{name}.rs"))
}
