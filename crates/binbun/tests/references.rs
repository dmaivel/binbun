//! Cross-references and strings of the checked-in fixtures
//! (`tests/fixtures`): calls, string addresses taken, relocated pointers,
//! AArch64 `adrp` pairs and `adr`, PE base relocations, and functions
//! that do not lift.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::cfg::FunctionId;
use binbun::references::{Kind, Origin, Reference};
use binbun::strings::{Encoding, MIN_SCANNED};
use binbun::summary::summaries;
use binbun_loader::{Image, Relocation};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The address of symbol `name`.
fn symbol(database: &Database<'_>, name: &str) -> u64 {
    database
        .names()
        .iter()
        .find(|(_, n)| *n == name)
        .map_or_else(|| panic!("no symbol {name}"), |(&address, _)| address)
}

/// The function at symbol `name`.
fn function(database: &Database<'_>, name: &str) -> FunctionId {
    database.function_at(symbol(database, name)).unwrap()
}

fn kinds(references: &[Reference]) -> Vec<Kind> {
    references.iter().map(|r| r.kind).collect()
}

#[test]
fn x86_64_elf_calls_strings_and_pointers() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let references = database.references();
    let checked = function(&database, "checked");

    // One call to classify, from checked.
    let to_classify = references.to(symbol(&database, "classify"));
    assert_eq!(kinds(to_classify), [Kind::Call]);
    assert_eq!(to_classify[0].function, Some(checked));

    // The two literals, each passed once; nothing else is text (the
    // relocated `__dso_handle`'s low bytes read as " @").
    let strings = database.strings(MIN_SCANNED);
    let texts: Vec<&str> = strings.iter().map(|s| s.text.as_str()).collect();
    assert_eq!(texts, ["negative", "%d\n"]);
    for string in &strings {
        assert_eq!(string.references, 1);
        assert_eq!(string.encoding, Encoding::Utf8);
        assert!(string.read_only);
    }
    let negative = strings[0].address;
    let taken = references.to(negative);
    assert_eq!(kinds(taken), [Kind::Address]);
    assert_eq!(taken[0].function, Some(checked));

    // What checked refers to: classify, fail, and the string.
    let from: Vec<(u64, Kind)> = references
        .from_function(checked)
        .map(|r| (r.target, r.kind))
        .collect();
    for wanted in [
        (symbol(&database, "classify"), Kind::Call),
        (symbol(&database, "fail"), Kind::Call),
        (negative, Kind::Address),
    ] {
        assert!(from.contains(&wanted), "{wanted:x?} not in {from:x?}");
    }

    // `__dso_handle` holds its own address, by a relative relocation; a
    // position-independent image is never scanned.
    let dso = symbol(&database, "__dso_handle");
    let pointers: Vec<&Reference> = references
        .to(dso)
        .iter()
        .filter(|r| r.from == dso)
        .collect();
    assert_eq!(pointers.len(), 1);
    assert_eq!(
        pointers[0].kind,
        Kind::Pointer(Origin::Relocation(Relocation::Relative))
    );
    assert!(!references.scanned());
    assert_eq!(references.unlifted(), []);

    // Building the index computed the summaries decompilation uses.
    assert_eq!(database.summaries(), &summaries(&image, database.program()));
}

#[test]
fn strings_referred_to_by_relocated_pointers() {
    let data = fixture("rodata-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let references = database.references();
    let strings = database.strings(MIN_SCANNED);
    // `.rodata` shares the executable segment with `.text` here.
    for text in ["zero", "one", "two"] {
        let string = strings.iter().find(|s| s.text == text).unwrap();
        assert_eq!(
            kinds(references.to(string.address)),
            [Kind::Pointer(Origin::Relocation(Relocation::Relative))],
            "{text}"
        );
    }
    // `names` (24 bytes) is read by main, at an index.
    let names = database.object(symbol(&database, "names")).unwrap();
    assert_eq!(names.end - names.start, 24);
    let main = function(&database, "main");
    assert!(
        references
            .within(names)
            .iter()
            .any(|r| r.kind == Kind::Read && r.function == Some(main))
    );
}

#[test]
fn aarch64_addresses_from_adrp_and_adr() {
    // `adrp x8, table` then `ldr x0, [x8, :lo12:table + 8]`: a read of the
    // second entry, by the load.
    let data = fixture("dozen-aarch64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let entry = symbol(&database, "table_entry");
    let read = Reference {
        target: symbol(&database, "table") + 8,
        from: entry + 4,
        kind: Kind::Read,
        function: database.function_at(entry),
    };
    assert_eq!(
        database
            .references()
            .from_function(database.function_at(entry).unwrap())
            .copied()
            .collect::<Vec<_>>(),
        [read]
    );

    // `adr x3, .Lg_base` takes the address of the first of the four cases
    // the `br x2` jumps to.
    let data = fixture("resolve-aarch64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let guarded = function(&database, "guarded");
    let made: Vec<&Reference> = database.references().from_function(guarded).collect();
    let base = made
        .iter()
        .find(|r| r.kind == Kind::Address)
        .unwrap()
        .target;
    let table = made.iter().find(|r| r.target == base).unwrap().from + 8;
    let cases: Vec<u64> = made
        .iter()
        .filter(|r| r.kind == Kind::Jump && r.from == table)
        .map(|r| r.target)
        .collect();
    assert_eq!(cases, [base, base + 8, base + 16, base + 24]);
}

#[test]
fn pe_base_relocations_and_unlifted_code() {
    let data = fixture("program-x86_64.exe");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let references = database.references();
    let negative = database
        .strings(MIN_SCANNED)
        .into_iter()
        .find(|s| s.text == "negative")
        .unwrap();
    let taken = references.to(negative.address);
    assert_eq!(kinds(taken), [Kind::Address]);
    assert_eq!(taken[0].function, Some(function(&database, "checked")));
    // Base relocations state its pointers: no scanning.
    assert!(!references.scanned());

    // 32-bit x86 is not lifted: calls and jumps only.
    let data = fixture("program-i686.exe");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let references = database.references();
    assert_eq!(references.unlifted().len(), database.functions().count());
    let checked = function(&database, "_checked");
    let calls: Vec<u64> = references
        .from_function(checked)
        .filter(|r| r.kind == Kind::Call)
        .map(|r| r.target)
        .collect();
    assert_eq!(
        calls,
        [symbol(&database, "_classify"), symbol(&database, "_fail")]
    );
}
