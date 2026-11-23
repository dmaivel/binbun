//! Loading the checked-in Mach-O fixtures (`tests/fixtures`, built from
//! `program.c` and `exceptions.cpp` on a Mac by
//! `scripts/build-fixtures.sh macos`): a universal file's slices, each
//! slice's symbols, entry point, function starts, imports through binds
//! (`LC_DYLD_INFO_ONLY`'s opcodes for `x86_64`, chained fixups for `arm64`
//! and `arm64e`) and stubs, compact unwind ranges and exception tables.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_loader::{
    Format, Image, LoadError, Machine, PointerSource, SymbolKind, SymbolSource, UnwindSource,
    select, slices,
};
use binbun_semantics::core::Memory;

/// The functions `program.c` defines.
const FUNCTIONS: [&str; 5] = ["main", "classify", "fail", "checked", "loop_sum"];
/// The library every import of the fixtures comes from.
const LIBSYSTEM: &str = "/usr/lib/libSystem.B.dylib";
/// The slices of `program-universal.macho`, in the file's order.
const ARCHES: [(&str, Machine); 3] = [
    ("x86_64", Machine::X86_64),
    ("arm64", Machine::Aarch64),
    ("arm64e", Machine::Aarch64),
];

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn address_of(image: &Image<'_>, name: &str) -> u64 {
    image
        .symbols
        .iter()
        .find(|s| s.name == name && s.source == SymbolSource::Static)
        .unwrap_or_else(|| panic!("no symbol {name}"))
        .address
}

fn section_range(image: &Image<'_>, name: &str) -> core::ops::Range<u64> {
    let section = image
        .sections
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no section {name}: {:?}", image.sections));
    section.start..section.start + section.size
}

#[test]
fn a_universal_file_lists_its_slices_and_opens_the_one_asked_for() {
    let data = fixture("program-universal.macho");
    let found = slices(&data).unwrap();
    let named: Vec<(&str, Machine)> = found.iter().map(|s| (s.arch.as_str(), s.machine)).collect();
    assert_eq!(named, ARCHES);
    for slice in &found {
        let (bytes, chosen) = select(&data, Some(&slice.arch)).unwrap();
        assert_eq!(chosen.as_ref(), Some(slice));
        assert_eq!(Some(bytes), slice.bytes(&data));
        let image = Image::parse_arch(&data, Some(&slice.arch)).unwrap();
        assert_eq!(image.slice.as_ref(), Some(slice));
        assert_eq!(
            (image.format, image.machine),
            (Format::MachO, slice.machine)
        );
    }
    // Without one: the first slice for this machine's instruction set,
    // else the first.
    let host = if cfg!(target_arch = "aarch64") {
        Machine::Aarch64
    } else {
        Machine::X86_64
    };
    let default = Image::parse(&data).unwrap().slice.unwrap();
    let expected = found
        .iter()
        .find(|s| s.machine == host)
        .unwrap_or(&found[0]);
    assert_eq!(&default, expected);
    assert_eq!(
        Image::parse_arch(&data, Some("i386")).err(),
        Some(LoadError::NoSlice {
            arch: "i386".to_owned(),
            available: ARCHES.iter().map(|(arch, _)| (*arch).to_owned()).collect(),
        })
    );
    // A thin file is itself, whatever is asked for.
    let thin = found[1].bytes(&data).unwrap();
    assert_eq!(slices(thin).unwrap(), Vec::new());
    let image = Image::parse_arch(thin, Some("x86_64")).unwrap();
    assert_eq!((image.slice, image.machine), (None, Machine::Aarch64));
}

#[test]
fn a_damaged_universal_header_does_not_load() {
    let mut damaged = fixture("program-universal.macho");
    // The second slice's offset (big-endian, at 8 + 20 + 8) past the end.
    damaged[36..40].copy_from_slice(&0x7fff_0000u32.to_be_bytes());
    assert!(matches!(
        Image::parse_arch(&damaged, Some("arm64")),
        Err(LoadError::Parse(_))
    ));
    // The others still load.
    assert!(Image::parse_arch(&damaged, Some("x86_64")).is_ok());
}

#[test]
fn each_slice_has_its_symbols_entry_point_and_function_starts() {
    let data = fixture("program-universal.macho");
    for (arch, _) in ARCHES {
        let image = Image::parse_arch(&data, Some(arch)).unwrap();
        assert!(image.warnings.is_empty(), "{arch}: {:?}", image.warnings);
        assert_eq!(image.base, 0x1_0000_0000, "{arch}");
        assert!(image.position_independent, "{arch}");
        // `__PAGEZERO` maps nothing.
        assert!(!image.is_mapped(0), "{arch}");
        assert!(image.segments.iter().all(|s| s.start >= image.base));
        let text = section_range(&image, "__TEXT,__text");
        assert!(image.is_code(text.start), "{arch}");
        // The header, mapped executable with `__TEXT`, is no code.
        assert!(!image.is_code(image.base), "{arch}");
        assert_eq!(image.entry, Some(address_of(&image, "main")), "{arch}");
        for name in FUNCTIONS {
            let address = address_of(&image, name);
            assert!(text.contains(&address), "{arch}: {name}");
            assert!(
                image.function_starts.contains(&address),
                "{arch}: {name} at {address:#x} not among {:x?}",
                image.function_starts
            );
            // An executable exports its external symbols (the trie's).
            assert!(
                image.symbols.iter().any(|s| s.name == name
                    && s.address == address
                    && s.source == SymbolSource::Export
                    && s.kind == SymbolKind::Function),
                "{arch}: {name} not exported"
            );
        }
        // Names lose the C underscore: no `_main`.
        assert!(image.symbols.iter().all(|s| s.name != "_main"), "{arch}");
        assert!(
            image
                .symbols
                .iter()
                .any(|s| s.name == "_mh_execute_header" && s.address == image.base),
            "{arch}"
        );
        assert!(
            image
                .function_starts
                .iter()
                .all(|&start| text.contains(&start)),
            "{arch}: {:x?}",
            image.function_starts
        );
    }
}

#[test]
fn imports_come_from_binds_by_library() {
    let data = fixture("program-universal.macho");
    for (arch, _) in ARCHES {
        let image = Image::parse_arch(&data, Some(arch)).unwrap();
        for name in ["exit", "printf", "puts"] {
            let found: Vec<_> = image.imports.iter().filter(|i| i.name == name).collect();
            assert_eq!(found.len(), 1, "{arch}: {name}: {:?}", image.imports);
            let import = found[0];
            assert_eq!(import.library.as_deref(), Some(LIBSYSTEM), "{arch}");
            assert_eq!(import.size, 8, "{arch}");
            // The slot is written by the dynamic loader: its bytes in the
            // file (a chained fixup's link, a lazy pointer's stub helper)
            // are no value.
            assert!(
                image
                    .fixups
                    .iter()
                    .any(|f| f.start == import.slot && f.value.is_none()),
                "{arch}: {name}"
            );
            let in_relro = image.relro.iter().any(|r| r.contains(&import.slot));
            if arch == "x86_64" {
                // A lazy bind through `__la_symbol_ptr`, filled at the
                // first call.
                assert!(section_range(&image, "__DATA,__la_symbol_ptr").contains(&import.slot));
                assert!(!import.fixed && !in_relro, "{arch}: {import:?}");
            } else {
                // Chained fixups bind at load, in `__DATA_CONST`, which
                // the dynamic loader makes read-only after.
                let got = if arch == "arm64e" {
                    "__DATA_CONST,__auth_got"
                } else {
                    "__DATA_CONST,__got"
                };
                assert!(section_range(&image, got).contains(&import.slot), "{arch}");
                assert!(import.fixed && in_relro, "{arch}: {import:?}");
            }
        }
        if arch == "x86_64" {
            // The non-lazy bind of the stub helper's binder, in `__got`.
            let binder = image
                .imports
                .iter()
                .find(|i| i.name == "dyld_stub_binder")
                .unwrap();
            assert!(binder.fixed, "{binder:?}");
        }
        // The stubs that jump through the slots are code.
        let stubs = if arch == "arm64e" {
            "__TEXT,__auth_stubs"
        } else {
            "__TEXT,__stubs"
        };
        assert!(image.is_code(section_range(&image, stubs).start), "{arch}");
        // RELRO is `__DATA_CONST` (`SG_READ_ONLY`), not `__DATA`.
        let [relro] = image.relro.as_slice() else {
            panic!("{arch}: {:x?}", image.relro);
        };
        let data_const = image
            .sections
            .iter()
            .filter(|s| s.name.starts_with("__DATA_CONST,"))
            .all(|s| relro.contains(&s.start));
        assert!(data_const, "{arch}: {relro:x?}");
        assert!(
            image
                .sections
                .iter()
                .filter(|s| s.name.starts_with("__DATA,"))
                .all(|s| !relro.contains(&s.start)),
            "{arch}: {relro:x?}"
        );
    }
}

#[test]
fn compact_unwind_entries_are_cut_at_the_function_starts() {
    let data = fixture("program-universal.macho");
    for (arch, _) in ARCHES {
        let image = Image::parse_arch(&data, Some(arch)).unwrap();
        let entries: Vec<_> = image
            .unwind
            .iter()
            .filter(|u| u.source == UnwindSource::UnwindInfo)
            .collect();
        assert!(!entries.is_empty(), "{arch}");
        for entry in &entries {
            assert!(
                image.function_starts.contains(&entry.start),
                "{arch}: {entry:x?}"
            );
            let next = image
                .function_starts
                .iter()
                .find(|&&start| start > entry.start);
            assert!(
                next.is_none_or(|&next| entry.end <= next),
                "{arch}: {entry:x?}"
            );
        }
        for name in FUNCTIONS {
            let address = address_of(&image, name);
            assert!(
                entries.iter().any(|entry| entry.start == address),
                "{arch}: {name}"
            );
        }
    }
}

#[test]
fn lazy_pointers_hold_no_stub_helper_address() {
    // What the x86_64 slice rebases is its lazy pointers' initial values
    // (their stub helper entries), which a lazy bind replaces at the
    // first call: no pointer to code, no known value.
    let data = fixture("program-universal.macho");
    let image = Image::parse_arch(&data, Some("x86_64")).unwrap();
    for import in &image.imports {
        assert!(
            image.pointers.iter().all(|p| p.at != import.slot),
            "{import:?}"
        );
    }
    for pointer in &image.code_pointers {
        assert_ne!(pointer.source, PointerSource::Relocation, "{pointer:x?}");
    }
}

#[test]
fn exception_tables_come_from_the_compact_unwind_table() {
    let data = fixture("exceptions-universal.macho");
    for arch in ["x86_64", "arm64e"] {
        let image = Image::parse_arch(&data, Some(arch)).unwrap();
        assert!(image.warnings.is_empty(), "{arch}: {:?}", image.warnings);
        let guarded = address_of(&image, "_Z7guardedi");
        let table = image
            .exception_tables
            .iter()
            .find(|table| table.function == guarded)
            .unwrap_or_else(|| panic!("{arch}: {:x?}", image.exception_tables));
        let personality = table.personality.as_ref().unwrap();
        assert_eq!(
            personality.symbol.as_deref(),
            Some("__gxx_personality_v0"),
            "{arch}"
        );
        assert!(
            image
                .landing_pads
                .iter()
                .any(|pad| pad.function == guarded && image.is_code(pad.address)),
            "{arch}: {:x?}",
            image.landing_pads
        );
        // Read through the slot of the personality routine's import.
        let slot = personality.slot.unwrap();
        assert!(image.imports.iter().any(|i| i.slot == slot), "{arch}");
        assert!(image.region(slot).is_some(), "{arch}");
    }
}
