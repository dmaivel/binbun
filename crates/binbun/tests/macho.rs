//! Analysis of the checked-in Mach-O fixtures (`tests/fixtures`, built
//! from `program.c` and `exceptions.cpp` on a Mac by
//! `scripts/build-fixtures.sh macos`), slice by slice: recovery finds
//! every function the linker lists in `LC_FUNCTION_STARTS` and names the
//! stubs (arm64e's authenticate their target with `braa`) by their
//! imports; `printf`'s format places its variadic argument (on the stack
//! under Apple's arm64 convention) and the reading view assumes away the
//! AArch64 stack-alignment checks and the arm64e return address's
//! authentication; the dSYM's slice is the image's by `LC_UUID`.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::{Decompiled, Options, View, threads};
use binbun::prototypes::Imports;
use binbun::queries::verify::{self, Verdict};
use binbun_debuginfo::info::dsym;
use binbun_loader::Image;

/// The slices of `program-universal.macho`, in the file's order
/// (`exceptions-universal.macho` has no plain arm64).
const ARCHES: [&str; 3] = ["x86_64", "arm64", "arm64e"];

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Function `name` of `database` decompiled to C in `view`.
fn decompiled(database: &Database<'_>, name: &str, view: View) -> Decompiled {
    let id = database.find_function(name).unwrap();
    let options = Options {
        style: Some("kr".to_owned()),
        view,
        ..Options::default()
    };
    database.decompile(id, &options).result.unwrap()
}

fn text(decompiled: &Decompiled) -> &str {
    &decompiled.c.as_ref().unwrap().text
}

/// The name of each import thunk of `database` (of `image`): the import
/// it jumps to, as its calls name it (a stub has no symbol of its own).
fn thunks(image: &Image<'_>, database: &Database<'_>) -> BTreeMap<u64, String> {
    Imports::new(image, database.program())
        .thunk_names()
        .map(|(entry, name)| (entry, name.to_owned()))
        .collect()
}

#[test]
fn every_slice_recovers_the_listed_function_starts_and_names_its_stubs() {
    for name in ["program-universal.macho", "exceptions-universal.macho"] {
        let data = fixture(name);
        for slice in binbun_loader::slices(&data).unwrap() {
            let arch = slice.arch.as_str();
            let image = Image::parse_arch(&data, Some(arch)).unwrap();
            assert!(!image.function_starts.is_empty(), "{name} {arch}");
            let database = Database::new(&image, Seeds::ALL).unwrap();
            for &start in &image.function_starts {
                assert!(
                    database.function_at(start).is_some(),
                    "{name} {arch}: no function at the listed start {start:#x}"
                );
            }
            if name != "program-universal.macho" {
                continue;
            }
            let stubs: Vec<_> = image
                .sections
                .iter()
                .filter(|s| s.name == "__TEXT,__stubs" || s.name == "__TEXT,__auth_stubs")
                .map(|s| s.start..s.start + s.size)
                .collect();
            let thunks = thunks(&image, &database);
            let named: BTreeSet<&str> = database
                .functions()
                .map(|(_, function)| function.entry)
                .filter(|entry| stubs.iter().any(|stub| stub.contains(entry)))
                .map(|entry| thunks[&entry].as_str())
                .collect();
            assert_eq!(
                named,
                BTreeSet::from(["exit", "printf", "puts"]),
                "{name} {arch}"
            );
        }
    }
}

#[test]
fn printf_takes_the_one_argument_its_format_says_where_the_convention_passes_it() {
    let data = fixture("program-universal.macho");
    for arch in ARCHES {
        let image = Image::parse_arch(&data, Some(arch)).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let main = decompiled(&database, "main", View::Reading);
        let call = text(&main)
            .lines()
            .find(|line| line.contains("printf(\"%d\\n\", "))
            .unwrap_or_else(|| panic!("{arch}: no printf of the format:\n{}", text(&main)));
        // The format and one argument: no argument registers past them
        // (the commas of `printf`'s own list, not of a call in it).
        let start = call.find("printf(").unwrap() + "printf(".len();
        let mut depth = 0usize;
        let mut separators = 0;
        for c in call[start..].chars() {
            match c {
                '(' => depth += 1,
                ')' if depth == 0 => break,
                ')' => depth -= 1,
                ',' if depth == 0 => separators += 1,
                _ => {}
            }
        }
        assert_eq!(separators, 1, "{arch}: {call}");
        // Apple's arm64 passes the unnamed argument on the stack, where
        // `main` stored it (8 bytes, of which `%d` reads 4); x86-64 in a
        // register: either way the value itself, not the frame's bytes.
        assert!(!call.contains("frame"), "{arch}: {call}");
        assert!(call.contains("loop_sum("), "{arch}: {call}");
    }
}

#[test]
fn returns_are_returns_and_the_reading_view_assumes_alignment_and_authentication() {
    let data = fixture("program-universal.macho");
    for arch in ARCHES {
        let image = Image::parse_arch(&data, Some(arch)).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        for function in ["main", "checked", "loop_sum"] {
            // Exact: a return to the address the caller left (through the
            // top-byte view, and arm64e's authentication) is no trick;
            // the checks stay.
            let exact = decompiled(&database, function, View::Exact);
            assert!(!text(&exact).contains("binbun_stack_trick"), "{arch}");
            assert_eq!(
                text(&exact).contains("BINBUN_TRAP_AUTHENTICATION"),
                arch == "arm64e",
                "{arch} {function}"
            );
            assert_eq!(
                text(&exact).contains("BINBUN_TRAP_STACK"),
                arch != "x86_64",
                "{arch} {function}"
            );
            // Reading: neither check nor the signing is left.
            let reading = decompiled(&database, function, View::Reading);
            for gone in ["binbun_stack_trick", "BINBUN_TRAP", "compute_pac"] {
                assert!(
                    !text(&reading).contains(gone),
                    "{arch} {function}: {gone} in\n{}",
                    text(&reading)
                );
            }
            let [_, aligned, authenticated, ..] = reading.stats.assumed.kinds;
            assert_eq!(aligned > 0, arch != "x86_64", "{arch} {function}");
            assert_eq!(
                authenticated,
                usize::from(arch == "arm64e"),
                "{arch} {function}"
            );
        }
    }
}

#[test]
fn the_dsym_slice_is_the_images_by_uuid() {
    let data = fixture("program-universal.macho");
    let debug =
        fixture("program-universal.macho.dSYM/Contents/Resources/DWARF/program-universal.macho");
    let mut mains = BTreeSet::new();
    for arch in ARCHES {
        let image = Image::parse_arch(&data, Some(arch)).unwrap();
        let (bytes, _) = binbun_loader::select(&data, Some(arch)).unwrap();
        let model = binbun_debuginfo::info::read(&debug, bytes).unwrap();
        let named = |name: &str| {
            model
                .functions
                .values()
                .find(|f| f.name.as_deref() == Some(name))
                .unwrap_or_else(|| panic!("{arch}: no {name}"))
                .entry
        };
        // The slice's own addresses: those of its symbols.
        for function in ["main", "classify", "checked", "loop_sum"] {
            let symbol = image
                .symbols
                .iter()
                .find(|s| s.name == function)
                .unwrap()
                .address;
            assert_eq!(named(function), symbol, "{arch} {function}");
        }
        mains.insert(named("main"));
        // One slice of the dSYM is no other image's.
        let own = dsym::slice(&debug, bytes).unwrap();
        for other in ARCHES.iter().filter(|&&other| other != arch) {
            let (theirs, _) = binbun_loader::select(&data, Some(other)).unwrap();
            assert!(dsym::slice(own, theirs).is_err(), "{arch} as {other}");
        }
    }
    // Each slice's `main` is its own.
    assert_eq!(mains.len(), ARCHES.len());
}

/// The cause of a decompilation failure or of a function not checkable:
/// its message without the parts that differ between functions (an
/// address with the instruction there, a node's id: `cannot print: e443:
/// not printable as C yet: constants over 128 bits` is `cannot print: not
/// printable as C yet: constants over 128 bits`).
fn cause(message: &str) -> String {
    let node = |part: &str| {
        part.strip_prefix(|c: char| c.is_ascii_lowercase())
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    };
    message
        .split(": ")
        .filter(|part| !part.starts_with("0x") && !node(part))
        .collect::<Vec<_>>()
        .join(": ")
}

/// The share `part / whole` as a percentage (100 of nothing).
fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        return 100.0;
    }
    #[expect(clippy::cast_precision_loss, reason = "counts far below 2^52")]
    let share = part as f64 * 100.0 / whole as f64;
    share
}

/// What the corpus test reports of one slice: recovered entries in
/// `__TEXT,__text` against `LC_FUNCTION_STARTS`, stubs named by their
/// imports, `decompile_all`'s failures by cause (exact view) and the
/// verdicts of verify (exact view, the CLI's default states).
fn report(name: &str, arch: Option<&str>, image: &Image<'_>, out: &mut String) {
    let label = format!("{name} {}", arch.unwrap_or("thin"));
    let database = match Database::new(image, Seeds::ALL) {
        Ok(database) => database,
        Err(error) => {
            writeln!(out, "{label}: not analysed: {error}").unwrap();
            return;
        }
    };
    let within = |section: &str| {
        image
            .sections
            .iter()
            .filter(|s| s.name == section)
            .map(|s| s.start..s.start + s.size)
            .collect::<Vec<_>>()
    };
    let text = within("__TEXT,__text");
    let in_text = |address: &u64| text.iter().any(|range| range.contains(address));
    let starts: BTreeSet<u64> = image
        .function_starts
        .iter()
        .copied()
        .filter(in_text)
        .collect();
    let entries: BTreeSet<u64> = database
        .functions()
        .map(|(_, function)| function.entry)
        .filter(in_text)
        .collect();
    let found = starts.intersection(&entries).count();
    let stubs: Vec<_> = [within("__TEXT,__stubs"), within("__TEXT,__auth_stubs")].concat();
    let imports: BTreeSet<&str> = image.imports.iter().map(|i| i.name.as_str()).collect();
    let stub_entries: Vec<u64> = database
        .functions()
        .map(|(_, function)| function.entry)
        .filter(|entry| stubs.iter().any(|stub| stub.contains(entry)))
        .collect();
    let thunks = thunks(image, &database);
    let named = stub_entries
        .iter()
        .filter(|entry| {
            thunks
                .get(entry)
                .is_some_and(|name| imports.contains(name.as_str()))
        })
        .count();
    writeln!(
        out,
        "{label}: functions {}, __text entries {} vs LC_FUNCTION_STARTS {}: recall {:.2}%, precision {:.2}%; stubs named {named}/{} ({:.2}%), imports {}",
        database.functions().count(),
        entries.len(),
        starts.len(),
        percent(found, starts.len()),
        percent(found, entries.len()),
        stub_entries.len(),
        percent(named, stub_entries.len()),
        image.imports.len(),
    )
    .unwrap();
    let mut failures: BTreeMap<String, usize> = BTreeMap::new();
    let mut decompiled = 0;
    let options = Options {
        style: Some("kr".to_owned()),
        ..Options::default()
    };
    database.decompile_all(
        &options,
        |output| output.result.map(|_| ()).map_err(|message| cause(&message)),
        |result| match result {
            Ok(()) => decompiled += 1,
            Err(cause) => *failures.entry(cause).or_default() += 1,
        },
    );
    writeln!(
        out,
        "  decompiled {decompiled}, failed {}: {failures:?}",
        failures.values().sum::<usize>()
    )
    .unwrap();
    let (mut agreed, mut differs, mut unchecked) = (0, Vec::new(), BTreeMap::new());
    verify::verify_all(
        &database,
        &verify::Options::default(),
        threads(),
        |v| match v.verdict {
            Verdict::Agreed(_) => agreed += 1,
            Verdict::Differs(_) => differs.push(v.entry),
            Verdict::NotCheckable(why) => {
                *unchecked.entry(cause(&why)).or_insert(0usize) += 1;
            }
        },
    );
    writeln!(
        out,
        "  verify (exact): agreed {agreed}, differs {} {differs:#x?}, not checkable {}: {unchecked:?}",
        differs.len(),
        unchecked.values().sum::<usize>()
    )
    .unwrap();
}

/// The Mach-O corpus (every file in `BINBUN_MACHO_CORPUS`, every slice):
/// recovery's recall and precision of the entries in `__TEXT,__text`
/// against `LC_FUNCTION_STARTS`, the stubs named by their imports,
/// decompilation failures by cause and verify's verdicts, printed; no
/// function may differ from its L1.
#[test]
#[ignore = "needs the Mach-O corpus (BINBUN_MACHO_CORPUS)"]
fn corpus() {
    let corpus = std::env::var("BINBUN_MACHO_CORPUS").expect("BINBUN_MACHO_CORPUS");
    let mut files: Vec<_> = std::fs::read_dir(&corpus)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    let mut out = String::new();
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let data = std::fs::read(path).unwrap();
        let arches: Vec<Option<String>> = match binbun_loader::slices(&data) {
            Ok(slices) if !slices.is_empty() => slices.into_iter().map(|s| Some(s.arch)).collect(),
            Ok(_) | Err(_) => vec![None],
        };
        for arch in &arches {
            match Image::parse_arch(&data, arch.as_deref()) {
                Ok(image) => report(&name, arch.as_deref(), &image, &mut out),
                Err(error) => writeln!(out, "{name} {arch:?}: not loaded: {error}").unwrap(),
            }
        }
    }
    eprintln!("{out}");
    assert!(
        out.lines()
            .filter(|line| line.contains("verify (exact)"))
            .all(|line| line.contains("differs 0 ")),
        "a function differs from its L1"
    );
}
