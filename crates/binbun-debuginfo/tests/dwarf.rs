#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! The DWARF reader against `llvm-dwarfdump`: a few functions' parameters
//! (names, types, entry registers) and a few structs' fields (names,
//! offsets, types) equal the tool's output.

use std::path::PathBuf;
use std::process::Command;

use binbun_debuginfo::info::DebugModel;
use binbun_debuginfo::info::model::{Place, Type};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn model(name: &str) -> DebugModel {
    let data = std::fs::read(fixture(name)).unwrap();
    let model = binbun_debuginfo::info::dwarf::read(&data).unwrap();
    assert!(model.damage.is_empty(), "{:?}", model.damage);
    model
}

/// One DIE of `llvm-dwarfdump --show-children --name=NAME`: its depth, tag
/// and the attributes' text.
#[derive(Debug)]
struct Die {
    depth: usize,
    tag: String,
    attributes: Vec<(String, String)>,
}

impl Die {
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// A string attribute's text: `("n")` is `n`; a type reference
    /// `(0x00000059 "int")` is `int`.
    fn quoted(&self, name: &str) -> Option<String> {
        let value = self.attribute(name)?;
        let start = value.find('"')?;
        let end = value.rfind('"')?;
        Some(value[start + 1..end].to_owned())
    }
}

/// The DIEs `llvm-dwarfdump` prints for `name` and its children, or `None`
/// if the tool is not installed.
fn dump(file: &str, name: &str) -> Option<Vec<Die>> {
    let output = Command::new("llvm-dwarfdump")
        .arg("--show-children")
        .arg(format!("--name={name}"))
        .arg(fixture(file))
        .output()
        .ok()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let mut dies: Vec<Die> = Vec::new();
    for line in text.lines() {
        if let Some((offset, rest)) = line.split_once(':')
            && offset.starts_with("0x")
            && let Some(tag) = rest.trim_start().strip_prefix("DW_TAG_")
        {
            // `0x...: DW_TAG_x` at the root, two more spaces per level.
            let depth = (rest.len() - rest.trim_start().len()) / 2;
            dies.push(Die {
                depth,
                tag: tag.trim().to_owned(),
                attributes: Vec::new(),
            });
        } else if let Some(attribute) = line.trim_start().strip_prefix("DW_AT_")
            && let Some((key, value)) = attribute.split_once('\t')
            && let Some(die) = dies.last_mut()
        {
            die.attributes.push((key.to_owned(), value.to_owned()));
        } else if line.trim_start().starts_with('[')
            && let Some(die) = dies.last_mut()
            && let Some((_, value)) = die.attributes.last_mut()
        {
            // A location list continues on the following lines.
            value.push('\n');
            value.push_str(line.trim());
        }
    }
    Some(dies)
}

/// `llvm-dwarfdump`'s type names keep qualifiers the model looks through.
fn unqualified(name: &str) -> String {
    name.replace("const ", "")
        .replace(" const", "")
        .replace("volatile ", "")
}

fn check_parameters(file: &str, functions: &[&str]) {
    let model = model(file);
    for &name in functions {
        let Some(dies) = dump(file, name) else {
            eprintln!("llvm-dwarfdump is not installed: skipped");
            return;
        };
        let subprogram = dies
            .iter()
            .find(|die| die.tag == "subprogram" && die.attribute("low_pc").is_some())
            .unwrap();
        let low_pc = subprogram.attribute("low_pc").unwrap();
        let entry =
            u64::from_str_radix(low_pc.trim_matches(['(', ')']).trim_start_matches("0x"), 16)
                .unwrap();
        let function = &model.functions[&entry];
        assert_eq!(function.name.as_deref(), Some(name));
        let returns = subprogram
            .quoted("type")
            .map_or_else(|| "void".to_owned(), |name| unqualified(&name));
        assert_eq!(model.display(function.returns), returns, "{name} returns");
        let parameters: Vec<&Die> = dies
            .iter()
            .filter(|die| die.tag == "formal_parameter" && die.depth == subprogram.depth + 1)
            .collect();
        assert_eq!(
            function.parameters.len(),
            parameters.len(),
            "{name}'s parameters"
        );
        for (ours, theirs) in function.parameters.iter().zip(parameters) {
            assert_eq!(ours.name, theirs.quoted("name"), "{name}");
            assert_eq!(
                model.display(ours.ty),
                unqualified(&theirs.quoted("type").unwrap()),
                "{name}"
            );
            // The register at entry: the location list's first entry, or a
            // single location.
            let location = theirs.attribute("location").unwrap();
            let register = location
                .split_whitespace()
                .skip_while(|word| !word.trim_start_matches('(').starts_with("DW_OP_reg"))
                .nth(1)
                .map(|register| register.trim_end_matches(')').to_lowercase());
            let ours = match ours.place_at(entry) {
                Some(Place::Register(register)) => Some((*register).to_owned()),
                Some(Place::Stack(_) | Place::Relative { .. } | Place::Other) | None => None,
            };
            assert_eq!(ours, register, "{name}'s entry register");
        }
    }
}

fn check_struct(file: &str, name: &str) {
    let model = model(file);
    let Some(dies) = dump(file, name) else {
        eprintln!("llvm-dwarfdump is not installed: skipped");
        return;
    };
    let structure = dies.iter().find(|die| die.tag == "structure_type").unwrap();
    let members: Vec<&Die> = dies
        .iter()
        .filter(|die| die.tag == "member" && die.depth == structure.depth + 1)
        .collect();
    let size = u64::from_str_radix(
        structure
            .attribute("byte_size")
            .unwrap()
            .trim_matches(['(', ')'])
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    let ours = model
        .types
        .iter()
        .find_map(|ty| {
            let Type::Composite(composite) = ty else {
                return None;
            };
            (composite.name.as_deref() == Some(name) && composite.size == Some(size))
                .then_some(composite)
        })
        .unwrap();
    assert_eq!(ours.fields.len(), members.len(), "{name}'s fields");
    for (field, member) in ours.fields.iter().zip(members) {
        assert_eq!(field.name, member.quoted("name"));
        let offset = member
            .attribute("data_member_location")
            .unwrap()
            .trim_matches(['(', ')'])
            .trim_start_matches("0x");
        assert_eq!(
            field.offset,
            u64::from_str_radix(offset, 16).unwrap(),
            "{name}.{:?}",
            field.name
        );
        assert_eq!(
            model.display(field.ty),
            unqualified(&member.quoted("type").unwrap())
        );
    }
}

#[test]
fn parameters_equal_llvm_dwarfdump() {
    check_parameters(
        "program-x86_64.debug",
        &["classify", "checked", "loop_sum", "main", "fail"],
    );
}

#[test]
fn struct_fields_equal_llvm_dwarfdump() {
    check_struct("handlers-gcc-x86_64.debug", "Error");
    check_struct("handlers-gcc-x86_64.debug", "Guard");
    check_struct("handlers-clang-x86_64.debug", "Error");
}

/// GCC's frame base is the canonical frame address, so `DW_OP_fbreg -36`
/// is the slot at CFA - 36 (`llvm-dwarfdump`: a location list entry
/// `[0x10c9, 0x10ef): DW_OP_fbreg -36`).
#[test]
fn frame_base_offsets_are_cfa_relative() {
    let gcc = model("handlers-gcc-x86_64.debug");
    let spans: Vec<_> = gcc
        .functions
        .values()
        .flat_map(|function| function.parameters.iter().chain(&function.locals))
        .flat_map(|variable| variable.location.iter())
        .filter(|span| span.range == (0x10c9..0x10ef))
        .collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].place, Place::Stack(-36));
}

/// Each function keeps the compilation unit it is defined in: two units,
/// named as the compiler was given them, in the directory it ran in (the
/// fixture's build maps it to `/src`).
#[test]
fn functions_keep_their_compilation_unit() {
    let model = model("units-x86_64.debug");
    let unit = |name: &str| {
        let function = model
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some(name))
            .unwrap();
        model.unit(function.unit.unwrap()).unwrap().path()
    };
    assert_eq!(model.units.len(), 2);
    assert_eq!(unit("main"), "/src/units-a.c");
    assert_eq!(unit("twice"), "/src/units-a.c");
    assert_eq!(unit("scale"), "/src/units-b.c");
    assert_eq!(unit("offset"), "/src/units-b.c");
}
