#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! The native databases (`windows-{x86_64,aarch64}-native.jsonl`, from
//! phnt) against Microsoft's public ntdll.pdb of the build their functions
//! are read from (Windows 11 24H2, ntdll.dll 10.0.26100.9711; x64's PDB
//! GUID C031D45B-0DA1-8A6E-74D0-6ED6AB2DD9E1 age 1, ARM64's
//! 3C5EF84B-93C5-2CDF-ED2C-9DF0ED581A58 age 1, from Microsoft's symbol
//! server; not checked in): the size of the TEB, the PEB, the loader's
//! structures and what they hold, and every field's offset and size.
//! Fields phnt names differently are matched by offset and size. Skipped
//! where the PDB is absent (`$BINBUN_NTDLL_PDB`, else
//! `~/.cache/binbun-model-data/pdb/ntdll.pdb`; `$BINBUN_NTDLL_ARM64_PDB`,
//! else `ntdll-arm64.pdb` there).
//!
//! And x86-64 glibc's thread control block as binbun declares it
//! ([`binbun::prototypes::glibc_tcb`]) against `tcbhead_t` in the debug
//! information of the glibc the libc pair is built from (skipped where
//! absent: `~/.cache/binbun-truth-data/glibc-r50`).

use std::path::PathBuf;

use binbun_ast::types::{Type as L2Type, Types};
use binbun_debuginfo::info::DebugModel;
use binbun_debuginfo::info::model::{Composite, Type as PdbType};
use binbun_typedb::types::Record;
use binbun_typedb::{Type, TypeId, TypeLibrary, embedded};

/// The structures compared: the PDB's tag, and the same tag in phnt.
const STRUCTURES: [&str; 9] = [
    "_TEB",
    "_PEB",
    "_NT_TIB",
    "_CLIENT_ID",
    "_PEB_LDR_DATA",
    "_LDR_DATA_TABLE_ENTRY",
    "_RTL_USER_PROCESS_PARAMETERS",
    "_UNICODE_STRING",
    "_LIST_ENTRY",
];

/// Where phnt's layout differs from this build's, as the PDB states it
/// (structure, what differs): two fields of this build's that phnt does
/// not declare yet, at the end of their structures. ARM64's are the same.
const DIFFERENCES: [(&str, &str); 4] = [
    ("_PEB", "size Some(2008) vs Some(2000)"),
    ("_PEB+0x7d0", "Win32ClientProcInfo (8 bytes) not in phnt"),
    (
        "_RTL_USER_PROCESS_PARAMETERS",
        "size Some(1104) vs Some(1096)",
    ),
    (
        "_RTL_USER_PROCESS_PARAMETERS+0x448",
        "AttributeList (8 bytes) not in phnt",
    ),
];

/// The PDB `$variable` names, else `file` in the oracle's directory.
fn pdb(variable: &str, file: &str) -> Option<Vec<u8>> {
    let path = std::env::var_os(variable).map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME")?)
                .join(".cache/binbun-model-data/pdb")
                .join(file)
                .into()
        },
        |path| Some(PathBuf::from(path)),
    )?;
    std::fs::read(path).ok()
}

/// The native database of Windows on `arch`, alone.
fn native(arch: &str) -> TypeLibrary {
    let (_, database) = embedded(arch, "windows")
        .into_iter()
        .find(|(_, database)| {
            database
                .header
                .inputs
                .iter()
                .any(|input| input.starts_with("phnt@"))
        })
        .unwrap();
    let mut library = TypeLibrary::new();
    library.add(database).unwrap();
    library
}

/// The record with key `key`.
fn record<'a>(library: &'a TypeLibrary, key: &str) -> &'a Record<TypeId> {
    library
        .types()
        .find_map(|(_, ty)| {
            let Type::Record(record) = ty else {
                return None;
            };
            (record.key == key).then_some(record)
        })
        .unwrap_or_else(|| panic!("no {key} in the native database"))
}

/// The fields of `record` (anonymous members' fields in their place) as
/// (byte offset, size, name), bit-fields left out.
fn database_fields(
    library: &TypeLibrary,
    record: &Record<TypeId>,
    base: u64,
    out: &mut Vec<(u64, u64, String)>,
) {
    for field in record.fields.iter().flatten() {
        if field.bit_width.is_some() {
            continue;
        }
        let offset = base + field.bit_offset.unwrap() / 8;
        match (&field.name, library.ty(field.ty)) {
            (None, Some(Type::Record(inner))) => database_fields(library, inner, offset, out),
            (name, _) => out.push((
                offset,
                library.size_of(field.ty).unwrap_or(0),
                name.clone().unwrap_or_default(),
            )),
        }
    }
}

/// The same of a PDB composite, but for the padding Microsoft's own
/// headers name (`Padding0`) where phnt's leaves it implicit.
fn pdb_fields(
    model: &DebugModel,
    composite: &Composite,
    base: u64,
    out: &mut Vec<(u64, u64, String)>,
) {
    for field in &composite.fields {
        let padding = field.name.as_deref().is_some_and(|name| {
            name.strip_prefix("Padding")
                .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()))
        });
        if field.bits.is_some() || padding {
            continue;
        }
        let offset = base + field.offset;
        let resolved = model.resolve(field.ty);
        match (&field.name, model.ty(resolved)) {
            (None, PdbType::Composite(inner)) => pdb_fields(model, inner, offset, out),
            (name, _) => out.push((
                offset,
                model.size(field.ty).unwrap_or(0),
                name.clone().unwrap_or_default(),
            )),
        }
    }
}

/// The differences between `arch`'s native database and ntdll.pdb
/// `data`'s layouts of [`STRUCTURES`].
fn differences(arch: &str, data: &[u8]) -> Vec<String> {
    let (model, ids) = binbun_debuginfo::info::pdb::named(data, &STRUCTURES).unwrap();
    let library = native(arch);
    let mut differences = Vec::new();
    let mut renamed = Vec::new();
    for (name, id) in STRUCTURES.iter().zip(ids) {
        let id = id.unwrap_or_else(|| panic!("ntdll.pdb defines no {name}"));
        let PdbType::Composite(composite) = model.ty(model.resolve(id)) else {
            panic!("{name} is no composite in ntdll.pdb");
        };
        let ours = record(&library, &format!("struct {name}"));
        if composite.size != ours.size {
            differences.push(format!(
                "{name}: size {:?} vs {:?}",
                composite.size, ours.size
            ));
        }
        let (mut theirs, mut mine) = (Vec::new(), Vec::new());
        pdb_fields(&model, composite, 0, &mut theirs);
        database_fields(&library, ours, 0, &mut mine);
        for (offset, size, field) in &theirs {
            // A union's members share an offset: any of phnt's there of
            // the same size matches, the same name first.
            let there: Vec<_> = mine.iter().filter(|(at, _, _)| at == offset).collect();
            let same = there
                .iter()
                .filter(|(_, ours_size, _)| ours_size == size)
                .min_by_key(|(_, _, ours_name)| ours_name != field);
            match (same, there.first()) {
                (Some((_, _, ours_name)), _) => {
                    if ours_name != field {
                        renamed.push(format!("{name}+{offset:#x}: {field} is phnt's {ours_name}"));
                    }
                }
                (None, Some((_, ours_size, ours_name))) => differences.push(format!(
                    "{name}+{offset:#x}: {field} ({size} bytes) vs {ours_name} ({ours_size} bytes)"
                )),
                (None, None) => differences.push(format!(
                    "{name}+{offset:#x}: {field} ({size} bytes) not in phnt"
                )),
            }
        }
    }
    eprintln!(
        "{arch}: renamed ({}):\n{}",
        renamed.len(),
        renamed.join("\n")
    );
    eprintln!(
        "{arch}: differences ({}):\n{}",
        differences.len(),
        differences.join("\n")
    );
    differences
}

#[test]
fn native_structures_match_ntdll_pdb() {
    let expected: Vec<String> = DIFFERENCES
        .iter()
        .map(|(at, what)| format!("{at}: {what}"))
        .collect();
    for (arch, variable, file) in [
        ("x86_64", "BINBUN_NTDLL_PDB", "ntdll.pdb"),
        ("aarch64", "BINBUN_NTDLL_ARM64_PDB", "ntdll-arm64.pdb"),
    ] {
        let Some(data) = pdb(variable, file) else {
            eprintln!("{arch}: skipped: no {file}");
            continue;
        };
        assert_eq!(differences(arch, &data), expected, "{arch}");
    }
}

#[test]
fn glibc_tcb_matches_glibc_debug_information() {
    let Some(path) = std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".cache/binbun-model-data/glibc-r50/root/usr/lib/debug/usr/lib/libc.so.6.debug")
    }) else {
        return;
    };
    let Ok(data) = std::fs::read(&path) else {
        eprintln!("skipped: no {}", path.display());
        return;
    };
    let model = binbun_debuginfo::info::dwarf::read(&data).unwrap();
    let composite = model
        .types
        .iter()
        .find_map(|ty| {
            let PdbType::Typedef { name, target } = ty else {
                return None;
            };
            let PdbType::Composite(composite) = model.ty(model.resolve(*target)) else {
                return None;
            };
            (name == "tcbhead_t").then_some(composite)
        })
        .expect("no tcbhead_t in glibc's debug information");
    let mut types = Types::new(64);
    let id = binbun::prototypes::glibc_tcb(&mut types);
    let Some(L2Type::Struct(ours)) = types.get(id) else {
        panic!("not a struct");
    };
    for field in &ours.fields {
        let name = field.name.as_deref().unwrap();
        let theirs = composite
            .fields
            .iter()
            .find(|theirs| theirs.name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("glibc's tcbhead_t has no {name}"));
        assert_eq!(theirs.offset, field.offset, "{name}");
        assert_eq!(
            model.size(theirs.ty),
            types.width(field.ty).map(|bits| bits / 8),
            "{name}"
        );
    }
}
