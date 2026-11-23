//! What an unstripped build states about each function, read from its
//! debug file: its DWARF prototype and locals ([`binbun_debuginfo`]), its
//! symbol (name and size, whether the compiler cloned it), its source
//! file.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use binbun_debuginfo::info::model::{DebugModel, Encoding, Type, TypeId};
use binbun_loader::Image;
use gimli::{AttributeValue, Dwarf, EndianSlice, Reader, RunTimeEndian, constants};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};
use serde::{Deserialize, Serialize};

use crate::cparse::Ty;

/// One function the debug information states.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Function {
    pub entry: u64,
    /// The source name.
    pub name: String,
    /// The symbol's name (`foo.isra.0` for a clone of `foo`).
    pub symbol: Option<String>,
    /// The symbol's size in bytes.
    pub size: Option<u64>,
    pub returns: Ty,
    pub parameters: Vec<Ty>,
    pub variadic: bool,
    /// Its own local variables (inlined callees' not).
    pub locals: usize,
    /// The source file defining it, where it exists here.
    pub source: Option<PathBuf>,
}

impl Function {
    /// A copy the compiler made with another interface (`.isra`,
    /// `.constprop`, `.part`): its prototype is not the source's.
    pub fn clone_of_source(&self) -> bool {
        self.symbol.as_deref().is_some_and(|s| s.contains('.'))
    }
}

/// The functions with code in executable memory of `image` the debug file
/// `debug` states, by entry; source files found by replacing the prefix
/// `from` of their paths with `to`. Assembly compilation units state no
/// C prototype: their functions are excluded, and their count returned.
pub fn functions(
    image: &Image<'_>,
    image_data: &[u8],
    debug: &Path,
    source: (&str, &Path),
) -> Result<(BTreeMap<u64, Function>, usize), String> {
    let data = std::fs::read(debug).map_err(|e| format!("{}: {e}", debug.display()))?;
    let model = binbun_debuginfo::info::read(&data, image_data)?;
    let file = object::File::parse(&*data).map_err(|e| format!("{}: {e}", debug.display()))?;
    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let sections = gimli::DwarfSections::load(|id| -> Result<Cow<'_, [u8]>, String> {
        file.section_by_name(id.name())
            .map_or(Ok(Cow::Borrowed(&[])), |section| {
                section.uncompressed_data().map_err(|e| e.to_string())
            })
    })?;
    let dwarf = sections.borrow(|section| EndianSlice::new(section, endian));
    let assembly = assembly_functions(&dwarf).map_err(|e| e.to_string())?;
    let mut symbols: BTreeMap<u64, (String, u64)> = BTreeMap::new();
    for symbol in file.symbols() {
        if symbol.kind() == object::SymbolKind::Text
            && let Ok(name) = symbol.name()
        {
            let entry = symbols
                .entry(symbol.address())
                .or_insert_with(|| (name.to_owned(), symbol.size()));
            // A plain name over a clone's or a local alias'.
            if entry.0.contains('.') && !name.contains('.') {
                *entry = (name.to_owned(), symbol.size());
            }
        }
    }
    let mut found = BTreeMap::new();
    let mut excluded = 0;
    for (&entry, function) in &model.functions {
        let executable = image
            .segment(entry)
            .is_some_and(|segment| segment.permissions.execute);
        if !executable {
            continue;
        }
        if assembly.contains(&entry) {
            excluded += 1;
            continue;
        }
        let symbol = symbols.get(&entry);
        let unit = function.unit.and_then(|unit| model.unit(unit));
        let path = unit.map(|unit| unit.path()).and_then(|path| {
            let path = path.strip_prefix("./").unwrap_or(&path).to_owned();
            let local = match path.strip_prefix(source.0) {
                Some(rest) => source.1.join(rest.trim_start_matches('/')),
                None if source.0.is_empty() => source.1.join(&path),
                None => return None,
            };
            local.is_file().then_some(local)
        });
        found.insert(
            entry,
            Function {
                entry,
                name: function
                    .name
                    .clone()
                    .or_else(|| symbol.map(|s| s.0.clone()))
                    .unwrap_or_else(|| format!("sub_{entry:x}")),
                symbol: symbol.map(|s| s.0.clone()),
                size: symbol.map(|s| s.1).filter(|&size| size > 0),
                returns: shape(&model, function.returns),
                parameters: function
                    .parameters
                    .iter()
                    .map(|p| shape(&model, p.ty))
                    .collect(),
                variadic: function.variadic,
                locals: function.locals.len(),
                source: path,
            },
        );
    }
    Ok((found, excluded))
}

/// Entries of subprograms in assembly compilation units. An absent or
/// unrecognised language is not sufficient to exclude a unit.
fn assembly_functions<R: Reader>(dwarf: &Dwarf<R>) -> Result<BTreeSet<u64>, gimli::Error> {
    let mut found = BTreeSet::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let root = unit.entry(unit.header.root_offset())?;
        let language = root.attr_value(constants::DW_AT_language);
        let producer = root
            .attr_value(constants::DW_AT_producer)
            .map(|value| dwarf.attr_string(&unit, value))
            .transpose()?
            .map(|value| value.to_string_lossy().map(Cow::into_owned))
            .transpose()?;
        if !matches!(
            language,
            Some(AttributeValue::Language(constants::DW_LANG_Mips_Assembler))
        ) && !producer
            .as_deref()
            .is_some_and(|p| p == "GNU AS" || p.starts_with("GNU AS "))
        {
            continue;
        }
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs()? {
            if entry.tag() == constants::DW_TAG_subprogram {
                let mut ranges = dwarf.die_ranges(&unit, entry)?;
                while let Some(range) = ranges.next()? {
                    found.insert(range.begin);
                }
                if let Some(AttributeValue::Addr(address)) =
                    entry.attr_value(constants::DW_AT_low_pc)
                {
                    found.insert(address);
                }
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::{BTreeSet, Dwarf, EndianSlice, RunTimeEndian, assembly_functions};

    #[test]
    fn assembly_units_have_no_scored_prototype_but_c_and_unknown_units_remain() {
        // DWARF 4: a CU with language and producer, containing a
        // subprogram with a low PC but no prototype attributes.
        let abbrev = [
            1, 0x11, 1, 0x13, 5, 0x25, 8, 0, 0, 2, 0x2e, 0, 0x11, 1, 0, 0, 0,
        ];
        let mut info = Vec::new();
        for (language, producer, entry) in [
            (0x8001u16, "other assembler", 0x1000u64),
            (0, "GNU AS 2.44", 0x2000),
            (0x000c, "GNU C 14", 0x3000),
            (0, "unknown", 0x4000),
        ] {
            let mut unit = vec![4, 0, 0, 0, 0, 0, 8, 1];
            unit.extend(language.to_le_bytes());
            unit.extend(producer.as_bytes());
            unit.extend([0, 2]);
            unit.extend(entry.to_le_bytes());
            unit.push(0);
            info.extend(u32::try_from(unit.len()).unwrap().to_le_bytes());
            info.extend(unit);
        }
        let dwarf = Dwarf::load(|id| -> Result<_, gimli::Error> {
            let bytes = match id {
                gimli::SectionId::DebugInfo => info.as_slice(),
                gimli::SectionId::DebugAbbrev => &abbrev,
                _ => &[],
            };
            Ok(EndianSlice::new(bytes, RunTimeEndian::Little))
        })
        .unwrap();
        assert_eq!(
            assembly_functions(&dwarf).unwrap(),
            BTreeSet::from([0x1000, 0x2000])
        );
    }
}

/// A source type as [`Ty`] (typedefs looked through, enums as their
/// underlying integer, pointers to anything one class).
fn shape(model: &DebugModel, id: TypeId) -> Ty {
    let id = model.resolve(id);
    match model.ty(id) {
        Type::Void => Ty::Void,
        Type::Base {
            bytes, encoding, ..
        } => match encoding {
            Encoding::Signed | Encoding::Char { signed: true } => Ty::Signed(*bytes),
            Encoding::Unsigned | Encoding::Char { signed: false } => Ty::Unsigned(*bytes),
            Encoding::Bool => Ty::Bool(*bytes),
            Encoding::Float => Ty::Float(*bytes),
            Encoding::Other => Ty::Other,
        },
        Type::Enum { bytes, signed, .. } => {
            if *signed {
                Ty::Signed(*bytes)
            } else {
                Ty::Unsigned(*bytes)
            }
        }
        Type::Pointer { .. } | Type::Array { .. } => Ty::Pointer,
        Type::Composite(_) => Ty::Struct,
        Type::Typedef { .. } | Type::Function { .. } | Type::Unknown => Ty::Other,
    }
}
