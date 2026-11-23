//! COFF objects and Microsoft `.lib` archives linked as one image
//! (`binbun_loader::relocatable`), on `coff-x86_64.lib` (MSVC's cl /O2 /Gy
//! and lib, from `coff-a.cpp` and `coff-b.cpp`) and `coff-imports.lib`
//! (an import library, `lib /def`): `scripts/build-fixtures.sh`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_loader::relocatable::{Linked, RelocationType, archive_members};
use binbun_loader::{Format, Image, SymbolKind};
use binbun_semantics::core::memory::Memory as _;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The objects of `archive`, owned.
fn objects(archive: &[u8]) -> Vec<(String, Vec<u8>)> {
    archive_members(archive)
        .unwrap()
        .objects
        .into_iter()
        .map(|(name, bytes)| (name, bytes.to_vec()))
        .collect()
}

fn link(objects: &[(String, Vec<u8>)]) -> Linked {
    let borrowed: Vec<(String, &[u8])> = objects
        .iter()
        .map(|(name, bytes)| (name.clone(), bytes.as_slice()))
        .collect();
    Linked::link(&borrowed).unwrap()
}

/// The address of function symbol `name`.
fn function(image: &Image<'_>, name: &str) -> u64 {
    let found: Vec<u64> = image
        .symbols
        .iter()
        .filter(|s| s.name == name && s.kind == SymbolKind::Function)
        .map(|s| s.address)
        .collect();
    assert_eq!(found.len(), 1, "{name}: {found:#x?}");
    found[0]
}

fn word(image: &Image<'_>, address: u64) -> u32 {
    let mut bytes = [0u8; 4];
    assert_eq!(image.read(address, &mut bytes), Ok(4), "{address:#x}");
    u32::from_le_bytes(bytes)
}

/// The target of the `call rel32` or `jmp [rip + rel32]` whose field is
/// at `field`.
fn relative(image: &Image<'_>, field: u64) -> u64 {
    (field + 4).wrapping_add_signed(i64::from(word(image, field).cast_signed()))
}

#[test]
fn archive_members_are_objects_by_their_own_names() {
    let archive = fixture("coff-x86_64.lib");
    let kinds = archive_members(&archive).unwrap();
    let names: Vec<&str> = kinds.objects.iter().map(|(n, _)| n.as_str()).collect();
    // In archive order (lib's, not the command line's).
    assert_eq!(names, ["coff-b.obj", "coff-a.obj"]);
    assert_eq!(kinds.imports, 0);
    assert!(kinds.skipped.is_empty(), "{:?}", kinds.skipped);
}

#[test]
fn import_libraries_hold_no_objects() {
    let archive = fixture("coff-imports.lib");
    let kinds = archive_members(&archive).unwrap();
    assert!(kinds.objects.is_empty(), "{:?}", kinds.objects);
    // Two short import objects and the import descriptors' objects.
    assert!(kinds.imports >= 2, "{}", kinds.imports);
}

#[test]
fn objects_link_as_a_pe_image() {
    let linked = link(&objects(&fixture("coff-x86_64.lib")));
    let image = linked.image();
    // Read as a PE image is: the Windows x64 convention.
    assert_eq!(image.format, Format::Pe);
    // `__ImageBase` is the base, a page below the first section.
    assert_eq!(image.base, Linked::BASE);
    assert!(
        image
            .segments
            .iter()
            .all(|s| s.start >= Linked::BASE + 0x1000)
    );
    // The COMDAT function both objects define alike is kept once: the
    // first object's (coff-b's, first in the archive).
    let twice = function(&image, "?twice@@YAHH@Z");
    assert_eq!(
        linked.member(twice).map(|m| m.name.as_str()),
        Some("coff-b.obj")
    );
    // Calls from both objects reach it.
    let use_b = function(&image, "use_b");
    assert_eq!(relative(&image, use_b + 5), twice);
    let use_a = function(&image, "use_a");
    assert!(
        linked
            .relocations_in(use_a..use_a + 16)
            .iter()
            .any(|r| r.symbol == "?twice@@YAHH@Z" && r.kind == RelocationType::Coff(4))
    );
    // Functions are sized to their sections: `twice` is 9 bytes.
    let size = |name: &str| {
        image
            .symbols
            .iter()
            .find(|s| s.name == name)
            .and_then(|s| s.size)
    };
    assert_eq!(size("?twice@@YAHH@Z"), Some(9));
    assert_eq!(size("use_b"), Some(16));
    // Compiler labels are no symbols.
    assert!(image.symbols.iter().all(|s| !s.name.starts_with('$')));
}

#[test]
fn comdat_copies_compiled_otherwise_are_kept() {
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _};
    // coff-a's copy of the COMDAT function `twice` changed by a byte, as
    // an inline function compiled otherwise in another object is.
    let mut objects = objects(&fixture("coff-x86_64.lib"));
    let (_, a) = objects
        .iter_mut()
        .find(|(name, _)| name == "coff-a.obj")
        .unwrap();
    let (start, size) = {
        let file = object::File::parse(a.as_slice()).unwrap();
        let twice = file
            .symbols()
            .find(|s| s.name() == Ok("?twice@@YAHH@Z"))
            .unwrap();
        let section = file
            .section_by_index(twice.section_index().unwrap())
            .unwrap();
        section.file_range().unwrap()
    };
    let first = usize::try_from(start).unwrap();
    assert!(size > 1);
    a[first] ^= 0xff;
    let linked = link(&objects);
    let image = linked.image();
    // Both copies are functions of the image under the name, each its
    // object's.
    let copies: Vec<u64> = image
        .symbols
        .iter()
        .filter(|s| s.name == "?twice@@YAHH@Z" && s.kind == SymbolKind::Function)
        .map(|s| s.address)
        .collect();
    assert_eq!(copies.len(), 2, "{copies:#x?}");
    let owners: Vec<&str> = copies
        .iter()
        .map(|&at| linked.member(at).unwrap().name.as_str())
        .collect();
    assert_eq!(owners, ["coff-b.obj", "coff-a.obj"]);
    // References resolve to the first (coff-b's), as before.
    let use_b = function(&image, "use_b");
    assert_eq!(relative(&image, use_b + 5), copies[0]);
}

#[test]
fn alternate_names_and_imports_resolve() {
    let linked = link(&objects(&fixture("coff-x86_64.lib")));
    let image = linked.image();
    let classify = function(&image, "classify");
    let default_hook = function(&image, "default_hook");
    // `hook` is `default_hook` (`/alternatename`): its call, and an alias.
    assert_eq!(relative(&image, classify + 0x2f), default_hook);
    assert_eq!(function(&image, "hook"), default_hook);
    // `call [__imp_imported]`: the import `imported`, a read-only slot
    // the loader fills, as in a PE image.
    let call_import = function(&image, "call_import");
    let slot = relative(&image, call_import + 6);
    assert_eq!(linked.imports.get("imported"), Some(&slot));
    assert!(
        linked
            .externals
            .keys()
            .all(|name| !name.contains("imported"))
    );
    let import = image.imports.iter().find(|i| i.slot == slot).unwrap();
    assert_eq!(
        (import.name.as_str(), import.size, import.fixed),
        ("imported", 8, true)
    );
    assert!(
        image
            .fixups
            .iter()
            .any(|f| f.start == slot && f.size == 8 && f.value.is_none())
    );
    assert!(!image.segment(slot).unwrap().permissions.write);
    // The tail call in `classify` reads the same slot.
    assert_eq!(relative(&image, classify + 0x5b), slot);
    let names: Vec<String> = linked
        .relocations_in(call_import..call_import + 16)
        .iter()
        .map(|r| format!("{} {}", r.kind_name(), r.symbol))
        .collect();
    assert_eq!(names, ["rel32 __imp_imported"]);
}

#[test]
fn jump_tables_count_from_the_image_base() {
    let linked = link(&objects(&fixture("coff-x86_64.lib")));
    let image = linked.image();
    let classify = function(&image, "classify");
    // `lea rdx, [__ImageBase]`.
    assert_eq!(relative(&image, classify + 0xf), Linked::BASE);
    // `mov ecx, [rdx + rax * 4 + table]`: the table's address from the
    // base, and its entries the cases' (`$LN4` at 0x1f, `$LN5` at 0x29).
    let table = Linked::BASE + u64::from(word(&image, classify + 0x16));
    assert_eq!(table, classify + 0x88);
    assert_eq!(
        Linked::BASE + u64::from(word(&image, table)),
        classify + 0x1f
    );
    assert_eq!(
        Linked::BASE + u64::from(word(&image, table + 4)),
        classify + 0x29
    );
    assert!(
        linked
            .relocations_in(table..table + 28)
            .iter()
            .all(|r| r.kind_name() == "addr32nb")
    );
}

#[test]
fn thread_locals_are_offsets_in_the_block() {
    let linked = link(&objects(&fixture("coff-x86_64.lib")));
    let image = linked.image();
    let bump = function(&image, "bump");
    // `mov r8d, SECREL counter`: the first variable of the `.tls$`
    // section, at offset 0.
    assert_eq!(word(&image, bump + 0x11), 0);
    let secrel: Vec<String> = linked
        .relocations_in(bump..bump + 0x22)
        .iter()
        .map(|r| format!("{} {}", r.kind_name(), r.symbol))
        .collect();
    assert_eq!(secrel, ["rel32 _tls_index", "secrel ?counter@@3HA"]);
    // Its initial value is in the thread-local segment.
    let tls = image.sections.iter().find(|s| s.name == ".tls$").unwrap();
    assert_eq!(word(&image, tls.start), 7);
}

#[test]
fn pdata_gives_unwind_entries() {
    let linked = link(&objects(&fixture("coff-x86_64.lib")));
    let image = linked.image();
    for name in ["classify", "use_b", "guarded_store", "weigh"] {
        let start = function(&image, name);
        let size = image
            .symbols
            .iter()
            .find(|s| s.name == name)
            .and_then(|s| s.size)
            .unwrap();
        assert!(
            image
                .unwind
                .iter()
                .any(|e| e.start == start && e.end <= start + size && !e.fragment),
            "{name}"
        );
    }
}

/// An MSVC alias object (`ALIASOBJ`): no machine, no sections, the weak
/// external `name` defaulting to `target`.
fn alias_object(name: &str, target: &str) -> Vec<u8> {
    let short = |text: &str| {
        let mut field = [0u8; 8];
        field[..text.len()].copy_from_slice(text.as_bytes());
        field
    };
    let mut data = Vec::new();
    // The file header: machine 0, no sections, the symbol table after it
    // (three records).
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&20u32.to_le_bytes());
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    // The target: external, undefined.
    data.extend_from_slice(&short(target));
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0i16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&[2, 0]);
    // The alias: weak external, one auxiliary record naming record 0.
    data.extend_from_slice(&short(name));
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0i16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&[0x69, 1]);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&[0; 10]);
    // An empty string table.
    data.extend_from_slice(&4u32.to_le_bytes());
    data
}

#[test]
fn alias_objects_name_functions_twice() {
    let mut objects = objects(&fixture("coff-x86_64.lib"));
    objects.push(("alias.obj".into(), alias_object("use_aa", "use_a")));
    let linked = link(&objects);
    let image = linked.image();
    assert_eq!(function(&image, "use_aa"), function(&image, "use_a"));
    let use_a = function(&image, "use_a");
    assert_eq!(
        linked.member(use_a).map(|m| m.name.as_str()),
        Some("coff-a.obj")
    );
}

#[test]
fn elf_and_coff_objects_do_not_mix() {
    let mut objects = objects(&fixture("coff-x86_64.lib"));
    let archive = fixture("sigs-gcc.a");
    let elf = archive_members(&archive).unwrap().objects;
    objects.push((elf[0].0.clone(), elf[0].1.to_vec()));
    let borrowed: Vec<(String, &[u8])> = objects
        .iter()
        .map(|(name, bytes)| (name.clone(), bytes.as_slice()))
        .collect();
    assert!(Linked::link(&borrowed).is_err());
}
