//! Loading the checked-in fixtures (`tests/fixtures`, built from
//! `program.c`, `exceptions.cpp` and `rodata.c` by
//! `scripts/build-fixtures.sh`) and damaged files.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_loader::{
    Clause, ExceptionTable, Format, Image, LandingPad, LoadError, Machine, Part, PointerSource,
    Section, SymbolKind, SymbolSource, UnwindSource,
};
use binbun_semantics::core::Memory;

/// The functions `program.c` defines.
const FUNCTIONS: [&str; 5] = ["main", "classify", "fail", "checked", "loop_sum"];
/// Their names in 32-bit x86 COFF symbol tables (cdecl adds an underscore).
const DECORATED: [&str; 5] = ["_main", "_classify", "_fail", "_checked", "_loop_sum"];
/// What MinGW-w64's UCRT build imports for the program (`printf` becomes
/// a call of the UCRT's `__stdio_common_vfprintf`).
const UCRT_IMPORTS: [&str; 3] = ["puts", "exit", "__stdio_common_vfprintf"];

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn address_of(image: &Image<'_>, name: &str) -> u64 {
    image
        .symbols
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no symbol {name}"))
        .address
}

fn section(image: &Image<'_>, name: &str) -> Section {
    image
        .sections
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no section {name}"))
        .clone()
}

/// The ranges of the executable segments of `image`.
fn executable_segments(image: &Image<'_>) -> Vec<core::ops::Range<u64>> {
    image
        .segments
        .iter()
        .filter(|s| s.permissions.execute)
        .map(|s| s.start..s.end())
        .collect()
}

/// Properties every loaded image has.
fn check_layout(image: &Image<'_>, functions: &[&str]) {
    for pair in image.segments.windows(2) {
        assert!(
            pair[0].end() <= pair[1].start,
            "segments overlap: {pair:x?}"
        );
    }
    let entry = image.entry.unwrap();
    assert!(image.is_code(entry), "entry {entry:#x} is not code");
    for name in functions {
        let address = address_of(image, name);
        assert!(image.is_code(address), "{name} at {address:#x} is not code");
    }
    for import in &image.imports {
        let region = image.region(import.slot).unwrap();
        assert!(
            region.contains(import.slot + u64::from(import.size) - 1),
            "{import:?} straddles a segment"
        );
    }
}

/// Each of `names` is imported exactly once, with a slot of `size` bytes.
fn check_imports(image: &Image<'_>, names: &[&str], size: u8) {
    for name in names {
        let found: Vec<_> = image.imports.iter().filter(|i| i.name == *name).collect();
        assert_eq!(found.len(), 1, "{name}: {found:?}");
        assert_eq!(found[0].size, size, "{name}");
    }
}

/// Whether the `size` bytes at `slot` lie inside one of the image's RELRO
/// ranges.
fn in_relro(image: &Image<'_>, slot: u64, size: u8) -> bool {
    image
        .relro
        .iter()
        .any(|range| range.start <= slot && slot + u64::from(size) <= range.end)
}

#[test]
fn elf_slots_are_fixed_only_when_bound_now_inside_relro() {
    // Linked without `-z now`: even the GOT slots RELRO protects are
    // filled lazily for all the image says (`GLOB_DAT` slots are bound at
    // load in practice, but nothing in the image promises it).
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    assert!(
        image
            .imports
            .iter()
            .any(|import| in_relro(&image, import.slot, import.size)),
        "{:x?}",
        image.imports
    );
    assert!(image.imports.iter().all(|import| !import.fixed));
    // Bound now, but RELRO ends inside its first 64 KiB page (AArch64
    // loaders' largest page), so no whole page of it is made read-only:
    // the slots stay writable.
    let data = fixture("resolve-aarch64.elf");
    let image = Image::parse(&data).unwrap();
    check_imports(&image, &["abort", "exit", "puts"], 8);
    assert!(image.relro.is_empty(), "{:x?}", image.relro);
    assert!(image.imports.iter().all(|import| !import.fixed));
}

#[test]
fn a_bound_now_elf_fixes_its_relro_slots_but_not_weak_ones() {
    // Arch's bash: `-z now -z relro`, `-fno-plt`; its weak undefined
    // symbols (which may be bound to 0) are these four.
    let Ok(data) = std::fs::read("/usr/bin/bash") else {
        return;
    };
    let image = Image::parse(&data).unwrap();
    let malloc = image.imports.iter().find(|i| i.name == "malloc").unwrap();
    assert!(malloc.fixed, "{malloc:x?}");
    for import in &image.imports {
        let weak = matches!(
            import.name.as_str(),
            "__gmon_start__"
                | "_ITM_registerTMCloneTable"
                | "_ITM_deregisterTMCloneTable"
                | "__cxa_finalize"
        );
        let expected = !weak && in_relro(&image, import.slot, import.size);
        assert_eq!(import.fixed, expected, "{import:x?}");
    }
}

/// An ELF import's library is the file of the version it needs
/// (`DT_VERNEED`'s `vn_file`): glibc's versioned functions come from
/// `libc.so.6`; the weak unversioned symbols GCC's start files reference
/// state none.
#[test]
fn elf_imports_name_the_library_their_version_needs() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    for import in &image.imports {
        let versioned = matches!(
            import.name.as_str(),
            "puts" | "printf" | "exit" | "__libc_start_main" | "__cxa_finalize"
        );
        let expected = versioned.then_some("libc.so.6");
        assert_eq!(import.library.as_deref(), expected, "{import:x?}");
    }
    assert!(image.imports.iter().any(|import| import.name == "puts"));
}

/// Unversioned imports state no library, even with one `DT_NEEDED`
/// (`libresolve.so`): the dynamic loader takes the first definition in
/// the global scope, which that library's own dependencies are part of.
#[test]
fn unversioned_elf_imports_name_no_library() {
    let data = fixture("resolve-aarch64.elf");
    let image = Image::parse(&data).unwrap();
    check_imports(&image, &["abort", "exit", "puts"], 8);
    assert!(image.imports.iter().all(|import| import.library.is_none()));
}

#[test]
fn pe_iat_slots_are_fixed_only_in_read_only_sections() {
    // MSVC puts the IAT in `.rdata`.
    let mut data = fixture("msvc-x86_64.exe");
    let image = Image::parse(&data).unwrap();
    check_imports(&image, &["__stdio_common_vfprintf"], 8);
    for import in &image.imports {
        assert!(!image.region(import.slot).unwrap().permissions.write);
        assert!(import.fixed, "{import:x?}");
    }
    // The same file with `.rdata` writable (`IMAGE_SCN_MEM_WRITE` set in
    // its section header): the program could change the slots.
    let headers = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    let sections = u16::from_le_bytes(data[headers + 6..headers + 8].try_into().unwrap());
    let optional = u16::from_le_bytes(data[headers + 20..headers + 22].try_into().unwrap());
    let table = headers + 24 + usize::from(optional);
    let rdata = (0..usize::from(sections))
        .map(|index| table + 40 * index)
        .find(|&at| &data[at..at + 8] == b".rdata\0\0")
        .unwrap();
    data[rdata + 39] |= 0x80;
    let image = Image::parse(&data).unwrap();
    check_imports(&image, &["__stdio_common_vfprintf"], 8);
    for import in &image.imports {
        assert!(image.region(import.slot).unwrap().permissions.write);
        assert!(!import.fixed, "{import:x?}");
    }
}

#[test]
fn loads_an_elf_executable() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    assert_eq!(
        (image.format, image.machine),
        (Format::Elf, Machine::X86_64)
    );
    assert!(image.warnings.is_empty(), "{:?}", image.warnings);
    check_layout(&image, &FUNCTIONS);
    check_imports(&image, &["puts", "printf", "exit"], 8);
    // Imports by `JUMP_SLOT` relocations land in the writable GOT.
    for import in &image.imports {
        assert!(
            image.region(import.slot).unwrap().permissions.write,
            "{import:?}"
        );
    }
    for name in FUNCTIONS {
        let symbol = image.symbols.iter().find(|s| s.name == name).unwrap();
        assert_eq!(symbol.kind, SymbolKind::Function, "{name}");
        let size = symbol.size.unwrap();
        // GCC emits one frame description entry per function, covering it.
        assert!(
            image
                .unwind
                .iter()
                .any(|u| u.source == UnwindSource::EhFrame
                    && u.start == symbol.address
                    && u.end == symbol.address + size),
            "{name} has no matching .eh_frame entry"
        );
    }
    // Memory: the code reads as the file stores it, and zero-filled `.bss`
    // reads as zeros up to the segment's end.
    let main = address_of(&image, "main");
    let segment = image.segment(main).unwrap();
    let mut bytes = [0u8; 16];
    assert_eq!(image.read(main, &mut bytes), Ok(16));
    let offset = usize::try_from(main - segment.start).unwrap();
    assert_eq!(bytes, segment.bytes[offset..offset + 16]);
    let last = image.segments.last().unwrap();
    let mut tail = vec![0xffu8; 64];
    let read = image.read(last.end() - 8, &mut tail).unwrap();
    assert_eq!(read, 8, "reads stop at the end of the mapping");
    assert_eq!(image.read(u64::MAX - 4, &mut tail), Ok(0));
}

/// x64 `.pdata` entries chained to a function's (`tests/fixtures/
/// chained.s`): each is a fragment of that function, by either form of
/// the chain (the chained entry after the unwind codes; an odd unwind RVA
/// pointing at the entry itself).
#[test]
fn chained_unwind_information_names_the_function_split_off() {
    let data = fixture("chained-x86_64.exe");
    let image = Image::parse(&data).unwrap();
    let main = image.entry.unwrap();
    let entries: Vec<(u64, bool, Option<u64>)> = image
        .unwind
        .iter()
        .map(|u| (u.start - main, u.fragment, u.split_from))
        .collect();
    assert_eq!(
        entries,
        [
            (0, false, None),
            (0x10, true, Some(main)),
            (0x17, true, Some(main)),
        ]
    );
}

#[test]
fn loads_a_pe32_plus_executable() {
    let data = fixture("program-x86_64.exe");
    let image = Image::parse(&data).unwrap();
    assert_eq!((image.format, image.machine), (Format::Pe, Machine::X86_64));
    assert!(image.warnings.is_empty(), "{:?}", image.warnings);
    check_layout(&image, &FUNCTIONS);
    check_imports(&image, &UCRT_IMPORTS, 8);
    assert!(image.imports.iter().all(|i| i.library.is_some()));
    // MinGW gives every function a `.pdata` entry starting at it.
    for name in FUNCTIONS {
        let address = address_of(&image, name);
        assert!(
            image
                .unwind
                .iter()
                .any(|u| u.source == UnwindSource::Pdata && u.start == address && !u.fragment),
            "{name} at {address:#x} has no .pdata entry"
        );
    }
    assert!(image.unwind.windows(2).all(|w| w[0].start <= w[1].start));
    // PE sections are what is mapped: the code is the executable ones.
    assert_eq!(image.code, executable_segments(&image));
}

#[test]
fn loads_a_pe32_executable() {
    let data = fixture("program-i686.exe");
    let image = Image::parse(&data).unwrap();
    assert_eq!((image.format, image.machine), (Format::Pe, Machine::X86));
    check_layout(&image, &DECORATED);
    check_imports(&image, &UCRT_IMPORTS, 4);
    // 32-bit x86 PE files have no `.pdata`.
    assert_eq!(image.unwind, []);
}

/// `data` with its PE optional header's subsystem field set to
/// `subsystem`.
fn with_subsystem(mut data: Vec<u8>, subsystem: u16) -> Vec<u8> {
    let header = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    // The signature (4 bytes) and the file header (20): the optional
    // header's subsystem is 68 bytes into it, in PE32 and PE32+ alike.
    let at = header + 24 + 68;
    data[at..at + 2].copy_from_slice(&subsystem.to_le_bytes());
    data
}

#[test]
fn a_native_image_importing_from_the_kernel_is_kernel_mode_code() {
    const NATIVE: u16 = 1;
    const CONSOLE: u16 = 3;
    let kernel = |data: &[u8]| Image::parse(data).unwrap().kernel;
    // The driver: native, importing from ntoskrnl.exe.
    let driver = fixture("driver-x86_64.sys");
    assert!(kernel(&driver));
    // The same imports for the console subsystem: not the kernel's code.
    assert!(!kernel(&with_subsystem(driver, CONSOLE)));
    // Programs: user mode, and still so for the native subsystem (as
    // smss.exe is), which their imports from user-mode DLLs rule out.
    for name in ["program-x86_64.exe", "msvc-x86_64.exe", "program-i686.exe"] {
        let program = fixture(name);
        assert!(!kernel(&program), "{name}");
        assert!(!kernel(&with_subsystem(program, NATIVE)), "{name}");
    }
}

#[test]
fn finds_pointers_to_code_and_what_they_point_to() {
    // The ELF fixture's init and fini arrays hold `frame_dummy` and
    // `__do_global_dtors_aux`, relocated (relative relocations, possibly
    // packed in `.relr.dyn`).
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    for name in ["frame_dummy", "__do_global_dtors_aux"] {
        let address = address_of(&image, name);
        assert!(
            image.code_pointers.iter().any(|p| p.target == address),
            "no pointer to {name}"
        );
    }
    // `_init` and `_fini`: only the dynamic section names them.
    for name in ["_init", "_fini"] {
        let address = address_of(&image, name);
        assert!(
            image
                .code_pointers
                .iter()
                .any(|p| p.target == address && p.source == PointerSource::DynamicTag),
            "no dynamic tag for {name}"
        );
    }
    for pointer in &image.code_pointers {
        // Each is stored in the image and points to code. (What the file
        // stores there depends on the relocation format: the target with
        // `REL`/`RELR`, often 0 with `RELA`, whose addend holds it.)
        assert!(image.region(pointer.at).is_some(), "{pointer:x?}");
        assert!(image.is_code(pointer.target));
    }

    // The x64 PE fixture: base relocations, and the exception handler of
    // MinGW's unwind information.
    let data = fixture("program-x86_64.exe");
    let image = Image::parse(&data).unwrap();
    let sources: Vec<PointerSource> = image.code_pointers.iter().map(|p| p.source).collect();
    assert!(sources.contains(&PointerSource::Relocation));
    assert!(sources.contains(&PointerSource::UnwindHandler));
    assert!(image.code_pointers.iter().all(|p| image.is_code(p.target)));
}

#[test]
fn only_executable_sections_are_code() {
    // Linked with `-z noseparate-code`: one R+X segment maps the headers,
    // `.text` and `.rodata`.
    let data = fixture("rodata-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    assert!(image.warnings.is_empty(), "{:?}", image.warnings);
    check_layout(&image, &["main", "twice", "square"]);
    let (text, rodata) = (section(&image, ".text"), section(&image, ".rodata"));
    let segment = image.segment(text.start).unwrap();
    assert!(segment.permissions.execute);
    assert_eq!(image.segment(rodata.start), Some(segment));

    assert!(image.is_code(text.start) && image.is_code(text.start + text.size - 1));
    assert!(!image.is_code(rodata.start) && !image.is_code(rodata.start + rodata.size - 1));
    assert!(!image.is_code(segment.start), "the ELF header is code");
    assert!(!image.is_code(text.start + text.size + 0x1000));

    // The data holds pointers to `.rodata` (the strings of `names`) and to
    // code (`operations`): only the latter are pointers to code.
    let in_rodata = |address: u64| (rodata.start..rodata.start + rodata.size).contains(&address);
    assert!(
        image
            .fixups
            .iter()
            .filter_map(|f| f.value)
            .filter(|&value| in_rodata(value))
            .count()
            >= 3,
        "{:x?}",
        image.fixups
    );
    for name in ["twice", "square"] {
        let address = address_of(&image, name);
        assert!(
            image.code_pointers.iter().any(|p| p.target == address),
            "no pointer to {name}"
        );
    }
    assert!(image.code_pointers.iter().all(|p| image.is_code(p.target)));

    // Memory stays as mapped; the code view makes `.rodata` not executable.
    assert!(image.region(rodata.start).unwrap().permissions.execute);
    let view = image.code_view();
    let data_region = view.region(rodata.start).unwrap();
    assert!(!data_region.permissions.execute);
    assert!(data_region.start >= text.start + text.size);
    assert_eq!(data_region.end, segment.end());
    let main = address_of(&image, "main");
    let code_region = view.region(main).unwrap();
    assert!(code_region.permissions.execute);
    assert_eq!(
        (code_region.start, code_region.end),
        (text.start, text.start + text.size)
    );
    let header_region = view.region(segment.start).unwrap();
    assert!(!header_region.permissions.execute);
    assert_eq!(header_region.start, segment.start);
    assert!(header_region.end <= text.start);
    let (mut direct, mut viewed) = ([0u8; 16], [0u8; 16]);
    assert_eq!(image.read(rodata.start, &mut direct), Ok(16));
    assert_eq!(view.read(rodata.start, &mut viewed), Ok(16));
    assert_eq!(direct, viewed);
}

#[test]
fn without_section_headers_executable_segments_are_code() {
    let mut data = fixture("rodata-x86_64.elf");
    let (text, rodata) = {
        let image = Image::parse(&data).unwrap();
        (
            section(&image, ".text").start,
            section(&image, ".rodata").start,
        )
    };
    // Drop the section headers: the ELF64 header's `e_shoff` (8 bytes at
    // 0x28), `e_shnum` and `e_shstrndx` (2 bytes each at 0x3c).
    data[0x28..0x30].fill(0);
    data[0x3c..0x40].fill(0);
    let image = Image::parse(&data).unwrap();
    assert_eq!(image.sections, []);
    assert_eq!(image.code, executable_segments(&image));
    assert!(image.is_code(text) && image.is_code(rodata));
    assert!(
        image
            .code_view()
            .region(rodata)
            .unwrap()
            .permissions
            .execute
    );
}

#[test]
fn the_base_is_where_the_file_is_linked_to_load() {
    // Position-independent ELF: 0. PE: the header's image base, which the
    // fixtures' linkers chose (x64 and x86 defaults).
    let base = |name| Image::parse(&fixture(name)).unwrap().base;
    assert_eq!(base("program-x86_64.elf"), 0);
    assert_eq!(base("program-x86_64.exe"), 0x1_4000_0000);
    assert_eq!(base("program-i686.exe"), 0x40_0000);
}

#[test]
fn finds_the_landing_pads_of_exception_tables() {
    let data = fixture("exceptions-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    assert!(image.warnings.is_empty(), "{:?}", image.warnings);
    assert_ne!(image.landing_pads.len(), 0, "no landing pads");
    for pad in &image.landing_pads {
        // A landing pad lies within its function's unwind range.
        let owner = image
            .unwind
            .iter()
            .find(|u| u.start == pad.function)
            .unwrap_or_else(|| panic!("{pad:x?}: no unwind entry"));
        assert!(
            owner.start < pad.address && pad.address < owner.end,
            "{pad:x?}"
        );
    }
    // guarded's catch block is one of them (possibly in its cold part).
    let guarded = address_of(&image, "_Z7guardedi");
    let cold = image
        .symbols
        .iter()
        .find(|s| s.name == "_Z7guardedi.cold")
        .map(|s| s.address);
    assert!(
        image
            .landing_pads
            .iter()
            .any(|p| p.function == guarded || Some(p.function) == cold),
        "{:x?}",
        image.landing_pads
    );
}

/// The exception table of `guarded` in `exceptions-x86_64.elf`.
fn guarded_table<'a>(image: &'a Image<'_>) -> &'a ExceptionTable {
    let guarded = address_of(image, "_Z7guardedi");
    image
        .exception_tables
        .iter()
        .find(|t| t.function == guarded)
        .unwrap_or_else(|| panic!("{:x?}", image.exception_tables))
}

#[test]
fn reads_the_call_sites_and_catch_clauses_of_exception_tables() {
    let data = fixture("exceptions-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let guarded = address_of(&image, "_Z7guardedi");
    let table = guarded_table(&image);
    // Reached through the indirect, pc-relative `DW.ref` slot the dynamic
    // loader fills.
    let personality = table.personality.as_ref().unwrap();
    assert_eq!(personality.symbol.as_deref(), Some("__gxx_personality_v0"));
    assert_eq!(personality.address, None);
    // `guarded` calls `risky` at +1 (a 5-byte call); its landing pad, the
    // catch block, is at +8. The type table entry is indirect: a GOT slot
    // the dynamic loader fills with libstdc++'s `type_info`.
    let [call_site] = &table.call_sites[..] else {
        panic!("{:x?}", table.call_sites);
    };
    assert_eq!(
        (call_site.start, call_site.end, call_site.landing_pad),
        (guarded + 1, guarded + 6, Some(guarded + 8))
    );
    let [Clause::Catch(type_info)] = &call_site.clauses[..] else {
        panic!("{:x?}", call_site.clauses);
    };
    // The type table's first entry: the pad compares the selector with 1.
    assert_eq!(call_site.selectors, [1]);
    assert_eq!(type_info.name.as_deref(), Some("std::exception"));
    assert_eq!(
        type_info
            .object
            .symbol
            .as_deref()
            .map(|s| s.split('@').next()),
        Some(Some("_ZTISt9exception"))
    );
    assert!(type_info.object.slot.is_some() && type_info.object.address.is_none());
    // Every landing pad of the tables is one of `landing_pads`, and the
    // other way round.
    let mut pads: Vec<LandingPad> = image
        .exception_tables
        .iter()
        .flat_map(|t| {
            t.call_sites.iter().filter_map(|c| {
                c.landing_pad.map(|address| LandingPad {
                    function: t.function,
                    address,
                })
            })
        })
        .collect();
    pads.sort_unstable_by_key(|p| (p.address, p.function));
    pads.dedup();
    assert_eq!(pads, image.landing_pads);
    // Without a landing pad, a call site has no clauses; a landing pad
    // without actions is a cleanup (the catch block's `__cxa_end_catch`).
    for call_site in image.exception_tables.iter().flat_map(|t| &t.call_sites) {
        assert_eq!(
            call_site.landing_pad.is_none(),
            call_site.clauses.is_empty(),
            "{call_site:x?}"
        );
        assert_eq!(call_site.clauses.len(), call_site.selectors.len());
    }
    assert!(
        image
            .exception_tables
            .iter()
            .flat_map(|t| &t.call_sites)
            .any(|c| c.clauses == [Clause::Cleanup] && c.selectors == [0])
    );
}

#[test]
fn keeps_what_precedes_the_damage_in_an_exception_table() {
    let data = fixture("exceptions-x86_64.elf");
    let lsda = guarded_table(&Image::parse(&data).unwrap()).lsda;
    let at = usize::try_from(lsda).unwrap();
    // `guarded`'s table: no landing-pad base, type table (pc-relative,
    // indirect) ending 13 bytes on, call-site table (ULEB128) of 4 bytes,
    // its one entry, then the action table: catch type 1, last action.
    assert_eq!(
        data[at..at + 11],
        [
            0xff, 0x9b, 0x0d, 0x01, 0x04, 0x01, 0x05, 0x08, 0x01, 0x01, 0x00
        ]
    );

    // The action's next one is itself.
    let mut looping = data.clone();
    looping[at + 10] = 0x7f;
    let image = Image::parse(&looping).unwrap();
    let [warning] = &image.warnings[..] else {
        panic!("{:?}", image.warnings);
    };
    assert_eq!(warning.part, Part::ExceptionTable);
    let table = guarded_table(&image);
    let [Clause::Catch(type_info)] = &table.call_sites[0].clauses[..] else {
        panic!("{:x?}", table.call_sites);
    };
    assert_eq!(type_info.name.as_deref(), Some("std::exception"));

    // A call-site table one byte longer: the second entry does not fit.
    let mut truncated = data.clone();
    truncated[at + 4] = 0x05;
    let image = Image::parse(&truncated).unwrap();
    assert_eq!(image.warnings.len(), 1, "{:?}", image.warnings);
    assert_eq!(guarded_table(&image).call_sites.len(), 1);

    // A call-site table longer than what is mapped: no call sites.
    let mut unreadable = data;
    unreadable[at + 4] = 0xff;
    unreadable[at + 5] = 0x7f;
    let image = Image::parse(&unreadable).unwrap();
    assert_eq!(image.warnings.len(), 1, "{:?}", image.warnings);
    assert_eq!(guarded_table(&image).call_sites, []);
    assert_eq!(image.exception_tables.len(), 4);
}

#[test]
fn rejects_what_is_not_an_executable() {
    assert!(matches!(Image::parse(b"\x7fELF"), Err(LoadError::Parse(_))));
    assert!(matches!(
        Image::parse(&[0u8; 4096]),
        Err(LoadError::Parse(_))
    ));
    let data = fixture("program-x86_64.elf");
    assert!(Image::parse(&data[..100]).is_err());
}

/// Damaged files load or fail; they never panic. Random byte changes at
/// random places, many times, on each fixture.
#[test]
fn damaged_files_do_not_panic() {
    let mut state = 0x1234_5678_9abc_def0u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for name in [
        "program-x86_64.elf",
        "program-x86_64.exe",
        "program-i686.exe",
        "rodata-x86_64.elf",
    ] {
        let original = fixture(name);
        for _ in 0..300 {
            let mut data = original.clone();
            // Damage mostly the headers and tables near the start.
            let span = if next() % 2 == 0 { 4096 } else { data.len() };
            for _ in 0..=next() % 8 {
                let at = usize::try_from(next()).unwrap() % span.min(data.len());
                data[at] = next().to_le_bytes()[0];
            }
            if let Ok(image) = Image::parse(&data) {
                let mut buffer = [0u8; 32];
                for segment in &image.segments {
                    let _ = image.read(segment.start, &mut buffer);
                    let _ = image.code_view().region(segment.start);
                    let _ = image.is_code(segment.start);
                }
            }
        }
    }
}

/// The system's libc reaches its own exported functions through GOT
/// slots (`GLOB_DAT`), and libstdc++'s vtables hold them in absolute words
/// (`R_X86_64_64`): each such slot holds the start of a function the
/// image defines in its code (as long as nothing interposes it); slots of
/// data (which an executable's copy relocation can move; a vtable's
/// typeinfo word points into another vtable) and of other modules'
/// symbols stay unknown.
#[test]
fn slots_of_the_image_s_own_functions_hold_their_address() {
    use object::elf::{R_X86_64_64, R_X86_64_GLOB_DAT, STT_FUNC};
    use object::{Object as _, ObjectSymbol as _, ObjectSymbolTable as _};
    use object::{RelocationFlags, RelocationTarget, SymbolFlags};

    for (path, checked) in [
        ("/usr/lib/libc.so.6", R_X86_64_GLOB_DAT),
        ("/usr/lib/libstdc++.so.6", R_X86_64_64),
    ] {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        let data = std::fs::read(path).unwrap();
        let image = Image::parse(&data).unwrap();
        let file = object::File::parse(&*data).unwrap();
        let symbols = file.dynamic_symbol_table().unwrap();
        let function = |symbol: &object::Symbol<'_, '_>| {
            matches!(symbol.flags(), SymbolFlags::Elf { st_info, .. }
                if st_info.st_type() == STT_FUNC)
        };
        let starts: std::collections::BTreeSet<u64> = symbols
            .symbols()
            .filter(|symbol| !symbol.is_undefined() && function(symbol))
            .map(|symbol| symbol.address())
            .collect();
        let (mut known, mut unknown) = (0, 0);
        for (at, relocation) in file.dynamic_relocations().unwrap() {
            let (RelocationFlags::Elf { r_type }, RelocationTarget::Symbol(index)) =
                (relocation.flags(), relocation.target())
            else {
                continue;
            };
            if ![R_X86_64_GLOB_DAT, R_X86_64_64].contains(&r_type) {
                continue;
            }
            let symbol = symbols.symbol_by_index(index).unwrap();
            let expected = (!symbol.is_undefined() && function(&symbol)).then(|| {
                symbol
                    .address()
                    .wrapping_add(relocation.addend().cast_unsigned())
            });
            let fixup = image.fixups.iter().find(|f| f.start == at).unwrap();
            assert_eq!(
                fixup.value,
                expected,
                "{path}: {:?} at {at:#x}",
                symbol.name()
            );
            if let Some(value) = fixup.value {
                assert!(
                    image.is_code(value) && starts.contains(&value),
                    "{path}: {:?} at {at:#x} holds {value:#x}",
                    symbol.name()
                );
            }
            match (r_type == checked, fixup.value) {
                (true, Some(_)) => known += 1,
                (true, None) => unknown += 1,
                (false, _) => {}
            }
        }
        assert!(
            known > 0 && unknown > 0,
            "{path}: {known} known, {unknown} unknown"
        );
    }
}

#[test]
fn exports_under_a_default_version_interpose() {
    // `exports-x86_64.s` with `exports-x86_64.map`: `malloc@@V2`,
    // `calloc@@V2` (protected) and `memcpy@@V2` interpose their names;
    // `memcpy@V1` (an older version), the hidden `free` and the local
    // `read` do not, nor does any static symbol table entry.
    let data = fixture("exports-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let mut interposing: Vec<(&str, u64)> = image
        .symbols
        .iter()
        .filter(|s| s.interposes)
        .inspect(|s| {
            assert_eq!(
                (s.source, s.kind),
                (SymbolSource::Dynamic, SymbolKind::Function)
            );
        })
        .map(|s| (s.name.as_str(), s.address))
        .collect();
    interposing.sort_unstable();
    let mut expected = vec![
        ("calloc", address_of(&image, "calloc")),
        ("malloc", address_of(&image, "malloc")),
        ("memcpy", address_of(&image, "memcpy_v2")),
    ];
    expected.sort_unstable();
    assert_eq!(interposing, expected);
    let old = address_of(&image, "memcpy_v1");
    assert!(
        image
            .symbols
            .iter()
            .any(|s| s.name == "memcpy" && s.address == old && s.source == SymbolSource::Dynamic),
        "memcpy@V1 is in .dynsym"
    );
}
