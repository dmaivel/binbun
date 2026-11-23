//! Library signatures (identities, fingerprints and behaviour checks) on
//! the `sigs.c` fixtures: one small library built several ways
//! (`scripts/build-fixtures.sh`).
//!
//! - Identity: the same function linked at two addresses, built with
//!   other registers fixed, with another block layout, and position
//!   independent, has one identity.
//! - Packs: made twice, byte-identical; checked; a second build merged.
//! - Behaviour: look-alikes told apart by their recordings (`strcpy` by
//!   its result, `memmove` by an overlapping copy, `strchr` by a character
//!   not in the string), a pair no state tells apart grouped, a function
//!   reading a word at a time run to completion on shaped states, and one
//!   that asks the processor what it is not checked.
//! - Matching: a linked build named from the archive's pack, with no wrong
//!   name.
//! - Aliases and forwarders: an identical definition in another object is
//!   one entry with an alias; forwarders to different callees are one
//!   group (a callee's name is not a difference: it is bound at match
//!   time); a forwarder recovery took together with its callee is split,
//!   so neither is named as the other.
//! - Sweeping: functions nothing reaches, found in the code no function
//!   covers and kept when a pack names them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::BTreeMap;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::corrections::Bounds;
use binbun::signatures::{self, How, MakeOptions, MatchOptions};
use binbun_loader::Image;
use binbun_loader::relocatable::{Linked, archive_members};
use binbun_sigpack::Identity;
use binbun_sigpack::pack::{Build, Check, Entry, Pack};

fn fixture(name: &str) -> (String, Vec<u8>) {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    (name.to_owned(), data)
}

fn options(build: &str) -> MakeOptions {
    MakeOptions {
        library: "sigs".into(),
        version: "1".into(),
        licence: "MIT".into(),
        build: build.into(),
        separators: true,
        ..MakeOptions::default()
    }
}

fn pack(names: &[&str], build: &str) -> Pack {
    let inputs: Vec<_> = names.iter().map(|name| fixture(name)).collect();
    signatures::make(&inputs, &options(build)).unwrap()
}

fn entry<'p>(pack: &'p Pack, name: &str) -> &'p Entry {
    pack.functions
        .iter()
        .find(|e| e.name == name || e.aliases.iter().any(|a| a == name))
        .unwrap_or_else(|| panic!("no {name} in the pack"))
}

fn build<'p>(pack: &'p Pack, name: &str) -> &'p Build {
    let entry = entry(pack, name);
    let id = entry.builds.keys().next().unwrap();
    pack.build(entry, id).unwrap()
}

fn identity(pack: &Pack, name: &str) -> Identity {
    build(pack, name).identity
}

/// The library's functions (not the linked builds' entry).
const FUNCTIONS: [&str; 13] = [
    "abs",
    "sig_error",
    "sig_has_avx",
    "sig_hash",
    "labs",
    "memcpy",
    "memmove",
    "stpcpy",
    "strchr",
    "strchrnul",
    "strcpy",
    "tolower",
    "tolower_l",
];

#[test]
fn identity_survives_addresses_layout_registers_and_pic() {
    let archive = pack(&["sigs-gcc.a"], "gcc");
    for (variant, except) in [
        // Linked at two addresses: every reference resolved.
        ("sigs-gcc-lo.elf", &[][..]),
        ("sigs-gcc-hi.elf", &[]),
        // Registers fixed: another allocation, the same code.
        ("sigs-gcc-r8.o", &[]),
        ("sigs-gcc-r1011.o", &[]),
        // Another block layout; the simple algorithm also rotates and
        // duplicates the loops of these four, which is other code.
        (
            "sigs-gcc-blocks.o",
            &["memmove", "stpcpy", "strchr", "strchrnul"],
        ),
        // Position independent: a switch's table of offsets is other
        // code, not other addresses.
        ("sigs-gcc-pie.o", &["sig_error"]),
    ] {
        let other = pack(&[variant], "other");
        for name in FUNCTIONS.into_iter().filter(|n| !except.contains(n)) {
            assert_eq!(
                identity(&archive, name),
                identity(&other, name),
                "{variant}: {name}"
            );
        }
    }
    // The variants do differ in their bytes.
    let registers = pack(&["sigs-gcc-r1011.o"], "registers");
    assert!(
        FUNCTIONS
            .iter()
            .any(|name| build(&archive, name).bytes != build(&registers, name).bytes)
    );
}

#[test]
fn packs_are_deterministic_and_merge() {
    let first = pack(&["sigs-gcc.a"], "gcc").write().unwrap();
    let second = pack(&["sigs-gcc.a"], "gcc").write().unwrap();
    assert_eq!(first, second, "the same inputs make the same pack");
    let mut read = Pack::read(&first).unwrap();
    assert_eq!(read.write().unwrap(), first, "a pack reads back to itself");
    let (errors, _) = read.check();
    assert!(errors.is_empty(), "{errors:?}");
    // A second build of the same functions: the identical ones refer to
    // the first.
    let mut r8 = pack(&["sigs-gcc-r8.o"], "r8");
    // The same objects, as another build of one library has them.
    for entry in &mut r8.functions {
        entry.object = "sigs-gcc.o".into();
    }
    read.merge(r8).unwrap();
    assert_eq!(read.header.builds.len(), 2);
    let (errors, _) = read.check();
    assert!(errors.is_empty(), "{errors:?}");
    let abs = entry(&read, "abs");
    assert_eq!(abs.builds.len(), 2);
    assert_eq!(
        read.build(abs, "r8").map(|b| b.identity),
        read.build(abs, "gcc").map(|b| b.identity)
    );
    // Another library does not merge.
    let mut other = pack(&["sigs-clang.o"], "clang");
    other.header.library = "other".into();
    assert!(read.merge(other).is_err());
}

/// The archive's objects linked as `sig make` links them, as a database.
fn linked() -> Linked {
    let (_, data) = fixture("sigs-gcc.a");
    let members: Vec<(String, &[u8])> = archive_members(&data).unwrap().objects;
    let owned: Vec<(String, Vec<u8>)> = members
        .into_iter()
        .map(|(name, bytes)| (name, bytes.to_vec()))
        .collect();
    let borrowed: Vec<(String, &[u8])> = owned
        .iter()
        .map(|(name, bytes)| (name.clone(), bytes.as_slice()))
        .collect();
    Linked::link(&borrowed).unwrap()
}

/// The recording of `name` in `pack`.
fn recording<'p>(pack: &'p Pack, name: &str) -> &'p binbun_sigpack::check::Recording {
    match &build(pack, name).check {
        Some(Check::Recorded(recording)) => recording,
        other => panic!("{name} has no recording: {other:?}"),
    }
}

#[test]
fn look_alikes_are_told_apart() {
    let pack = pack(&["sigs-gcc.a"], "gcc");
    let link = linked();
    let image = link.image();
    let db = Database::new(&image, Seeds::ALL).unwrap();
    let id = |name: &str| {
        let address = image
            .symbols
            .iter()
            .find(|s| s.name == name)
            .unwrap()
            .address;
        db.function_at(address).unwrap()
    };
    let replay = |function: &str, against: &str| {
        signatures::replay(&db, id(function), recording(&pack, against)).unwrap()
    };
    // Each agrees with its own recording.
    for name in ["strcpy", "stpcpy", "memcpy", "memmove", "strchr"] {
        let verdict = replay(name, name);
        assert!(verdict.agrees(), "{name}: {:?}", verdict.differs);
    }
    // strcpy returns the destination, stpcpy its end: the first state
    // tells them apart.
    let first = recording(&pack, "strcpy").states[0].state.number();
    let verdict = replay("stpcpy", "strcpy");
    assert_eq!(
        verdict.differs.as_ref().map(|d| d.0),
        Some(first),
        "{verdict:?}"
    );
    // memmove is not memcpy: some state (an overlapping or identical
    // pair of buffers, found by the states or by the separator search)
    // tells them apart, both ways.
    assert!(replay("memmove", "memcpy").differs.is_some());
    assert!(replay("memcpy", "memmove").differs.is_some());
    // strchr is not strchrnul (a character not in the string).
    assert!(replay("strchrnul", "strchr").differs.is_some());
    assert!(replay("strchr", "strchrnul").differs.is_some());
}

#[test]
fn word_reads_run_on_shaped_states() {
    let pack = pack(&["sigs-gcc.a"], "gcc");
    let recording = recording(&pack, "stpcpy");
    // Every random and shaped state ran (none undetermined by bytes past
    // the terminator).
    let numbers: Vec<u32> = recording.states.iter().map(|s| s.state.number()).collect();
    for number in 16..48 {
        assert!(
            numbers.contains(&number),
            "state {number} did not run: {numbers:?}"
        );
    }
}

#[test]
fn processor_dispatch_is_not_checked() {
    let pack = pack(&["sigs-gcc.a"], "gcc");
    assert!(build(&pack, "sig_has_avx").check.is_none());
    assert!(build(&pack, "sig_hash").check.is_some());
}

#[test]
fn matching_names_without_wrong_names() {
    let pack = pack(&["sigs-gcc.a"], "gcc");
    let (_, data) = fixture("sigs-gcc-hi.elf");
    let image = Image::parse(&data).unwrap();
    let db = Database::new(&image, Seeds::ALL).unwrap();
    let name_at = |address: u64| {
        image
            .symbols
            .iter()
            .filter(|s| s.address == address)
            .map(|s| s.name.clone())
            .collect::<Vec<_>>()
    };
    for behaviour in [false, true] {
        let options = MatchOptions {
            behaviour,
            sweep: false,
        };
        let matches = signatures::match_image(&db, std::slice::from_ref(&pack), options).unwrap();
        let mut named = Vec::new();
        for m in &matches {
            let Some((key, how)) = &m.named else { continue };
            let given = &pack.functions[key.1];
            let truth = name_at(m.entry);
            assert!(
                truth.contains(&given.name) || given.aliases.iter().any(|a| truth.contains(a)),
                "{:#x} named {} ({how:?}), is {truth:?}",
                m.entry,
                given.name
            );
            named.push(given.name.as_str());
        }
        // Every non-trivial function with its own identity is named (an
        // identical definition by its alias)...
        for name in ["stpcpy", "memcpy", "memmove", "sig_error", "sig_has_avx"] {
            assert!(
                named.contains(&name),
                "{name} not named ({behaviour}): {named:?}"
            );
        }
        // ...but those the library's forwarders pass their arguments to
        // as they are (hash_of to sig_hash, lower to tolower): with the
        // callee inlined, a forwarder is the callee, and none is here to
        // tell them apart. Both are listed.
        for (name, forwarder) in [("sig_hash", "hash_of"), ("tolower", "lower")] {
            assert!(!named.contains(&name), "{name} named ({behaviour})");
            let m = matches
                .iter()
                .find(|m| name_at(m.entry).contains(&name.to_owned()))
                .unwrap();
            let listed: Vec<&str> = m
                .candidates
                .iter()
                .map(|key| pack.functions[key.1].name.as_str())
                .collect();
            assert!(
                listed.contains(&name) && listed.contains(&forwarder),
                "{name}: {listed:?} {:?}",
                m.why
            );
        }
        if behaviour {
            // strcpy is trivial (a call and a return): named only by its
            // behaviour.
            let strcpy = matches
                .iter()
                .find(|m| name_at(m.entry).contains(&"strcpy".to_owned()))
                .unwrap();
            assert!(
                matches!(strcpy.named, Some((_, How::Behaviour { .. }))),
                "{strcpy:?}"
            );
        }
    }
}

#[test]
fn another_compiler_names_nothing_wrongly() {
    let pack = pack(&["sigs-clang.o"], "clang");
    let (_, data) = fixture("sigs-gcc-hi.elf");
    let image = Image::parse(&data).unwrap();
    let db = Database::new(&image, Seeds::ALL).unwrap();
    let options = MatchOptions {
        behaviour: true,
        sweep: false,
    };
    let matches = signatures::match_image(&db, std::slice::from_ref(&pack), options).unwrap();
    let mut named = 0;
    for m in &matches {
        let Some((key, _)) = &m.named else { continue };
        named += 1;
        let given = &pack.functions[key.1];
        assert!(
            image.symbols.iter().any(|s| s.address == m.entry
                && (s.name == given.name || given.aliases.contains(&s.name))),
            "{:#x} named {}",
            m.entry,
            given.name
        );
    }
    assert!(named >= 1, "nothing named");
}

#[test]
fn identical_definitions_are_one_entry() {
    let pack = pack(&["sigs-gcc.a"], "gcc");
    // sig_hash_copy (sigs-wrap.c) is sig_hash's code in another object.
    assert_eq!(entry(&pack, "sig_hash").aliases, ["sig_hash_copy"]);
    assert!(pack.functions.iter().all(|e| e.name != "sig_hash_copy"));
    // tolower_l, which ignores its locale, is tolower's code.
    assert_eq!(entry(&pack, "tolower").aliases, ["tolower_l"]);
    assert_eq!(entry(&pack, "tolower").copies, 2);
    // Forwarders have one (trivial) identity, but call other functions:
    // two entries.
    assert_eq!(identity(&pack, "hash_of"), identity(&pack, "lower"));
    assert_eq!(entry(&pack, "hash_of").aliases, Vec::<String>::new());
}

#[test]
fn forwarders_to_other_callees_are_one_group() {
    let pack = pack(&["sigs-gcc.a"], "gcc");
    // Which function a forwarder calls is bound when a binary is matched,
    // so no state tells hash_of (to sig_hash) from lower (to tolower).
    let group = entry(&pack, "hash_of").group.clone();
    assert!(group.is_some());
    assert_eq!(entry(&pack, "lower").group, group);
    assert!(
        entry(&pack, "hash_of")
            .separators
            .iter()
            .all(|s| s.from != "lower")
    );
}

#[test]
fn a_forwarder_and_its_callee_are_split() {
    let pack = pack(&["sigs-gcc.a"], "gcc");
    let (_, data) = fixture("sigs-wrap-gcc.elf");
    let image = Image::parse(&data).unwrap();
    // Without its symbols, recovery takes sig_hash, reached only by
    // hash_of's jump, into hash_of.
    let db = Database::new(&image, Seeds::ENTRY).unwrap();
    let address = |name: &str| {
        image
            .symbols
            .iter()
            .find(|s| s.name == name)
            .unwrap()
            .address
    };
    assert!(db.function_at(address("sig_hash")).is_none());
    let options = MatchOptions {
        behaviour: true,
        sweep: false,
    };
    let matches = signatures::match_image(&db, std::slice::from_ref(&pack), options).unwrap();
    for m in &matches {
        let Some((key, how)) = &m.named else { continue };
        let given = &pack.functions[key.1];
        let right = image.symbols.iter().any(|s| {
            s.address == m.entry && (s.name == given.name || given.aliases.contains(&s.name))
        });
        assert!(right, "{:#x} named {} ({how:?})", m.entry, given.name);
    }
    let at = |name: &str| matches.iter().find(|m| m.entry == address(name));
    let named = |name: &str| {
        at(name)
            .and_then(|m| m.named.as_ref())
            .map(|(key, _)| pack.functions[key.1].name.as_str())
    };
    // The callee split off, found and named; its copy named by its alias.
    assert_eq!(named("sig_hash"), Some("sig_hash"));
    assert!(at("sig_hash").unwrap().found);
    assert_eq!(named("sig_hash_copy"), Some("sig_hash"));
    // hash_of fits its own recording and lower's (one group); lower's call
    // would go to the function named sig_hash, which rules lower out.
    assert!(matches!(
        at("hash_of").unwrap().named,
        Some((key, How::Behaviour { .. })) if pack.functions[key.1].name == "hash_of"
    ));
}

#[test]
fn sweeping_finds_what_nothing_reaches() {
    let pack = pack(&["sigs-gcc.a"], "gcc");
    let (_, data) = fixture("sigs-wrap-gcc.elf");
    let image = Image::parse(&data).unwrap();
    let db = Database::new(&image, Seeds::ENTRY).unwrap();
    let address = |name: &str| {
        image
            .symbols
            .iter()
            .find(|s| s.name == name)
            .unwrap()
            .address
    };
    // wrap_start reaches none of sigs.c's string functions.
    for name in ["memmove", "stpcpy", "sig_error"] {
        assert!(db.function_at(address(name)).is_none(), "{name}");
    }
    let named_with = |sweep: bool| {
        let options = MatchOptions {
            behaviour: true,
            sweep,
        };
        let matches = signatures::match_image(&db, std::slice::from_ref(&pack), options).unwrap();
        matches
            .into_iter()
            .filter_map(|m| {
                let (key, _) = m.named?;
                Some((m.entry, m.found, pack.functions[key.1].clone()))
            })
            .collect::<Vec<_>>()
    };
    let without = named_with(false);
    let with = named_with(true);
    for (entry, _, given) in &with {
        let right = image.symbols.iter().any(|s| {
            s.address == *entry && (s.name == given.name || given.aliases.contains(&s.name))
        });
        assert!(right, "{entry:#x} named {}", given.name);
    }
    for name in ["memmove", "stpcpy", "sig_error"] {
        assert!(without.iter().all(|&(entry, ..)| entry != address(name)));
        assert!(
            with.iter()
                .any(|(entry, found, given)| *entry == address(name)
                    && *found
                    && given.name == name),
            "{name} not found"
        );
    }
}

#[test]
fn functions_the_packs_find_are_functions_once_adopted() {
    // Adopting what the packs found (a correction each, as the session
    // does) makes a function at every one of them: a name is never
    // proposed for what recovery would not take as a function.
    let pack = pack(&["sigs-gcc.a"], "gcc");
    let (_, data) = fixture("sigs-wrap-gcc.elf");
    let image = Image::parse(&data).unwrap();
    let db = Database::new(&image, Seeds::ENTRY).unwrap();
    for sweep in [false, true] {
        let options = MatchOptions {
            behaviour: true,
            sweep,
        };
        let matches = signatures::match_image(&db, std::slice::from_ref(&pack), options).unwrap();
        let found: Vec<u64> = matches
            .iter()
            .filter(|m| m.found)
            .map(|m| m.entry)
            .collect();
        assert!(!found.is_empty(), "sweep {sweep}: nothing found");
        let mut corrections = db.corrections().clone();
        for &entry in &found {
            corrections.set_bounds(entry, Some(Bounds::Function { end: None }));
        }
        let adopted = Database::with_corrections(&image, db.seeds(), None, corrections).unwrap();
        for entry in found {
            assert!(
                adopted.function_at(entry).is_some(),
                "sweep {sweep}: {entry:#x}"
            );
        }
    }
}

#[test]
fn a_name_is_not_given_at_more_addresses_than_the_library_has() {
    // The library linked (no forwarder to tolower in it).
    let mut pack = pack(&["sigs-gcc-lo.elf"], "gcc");
    let (_, data) = fixture("sigs-gcc-hi.elf");
    let image = Image::parse(&data).unwrap();
    let db = Database::new(&image, Seeds::ALL).unwrap();
    let options = MatchOptions {
        behaviour: true,
        sweep: false,
    };
    let tolower = |pack: &Pack| {
        let matches = signatures::match_image(&db, std::slice::from_ref(pack), options).unwrap();
        matches
            .into_iter()
            .filter(|m| {
                m.named
                    .as_ref()
                    .is_some_and(|(key, _)| pack.functions[key.1].name == "tolower")
            })
            .count()
    };
    // tolower and tolower_l are one code in two places: both named.
    assert_eq!(tolower(&pack), 2);
    // Were the library to have that code once, one of the two would be
    // another function behaving the same: neither is named.
    let index = pack
        .functions
        .iter()
        .position(|e| e.name == "tolower")
        .unwrap();
    pack.functions[index].copies = 1;
    assert_eq!(tolower(&pack), 0);
}

/// The names `packs` give `sigs-gcc-hi.elf`'s functions, with the pack
/// each comes from and how.
fn named_hi(packs: &[Pack]) -> Vec<(u64, usize, String, bool)> {
    let (_, data) = fixture("sigs-gcc-hi.elf");
    let image = Image::parse(&data).unwrap();
    let db = Database::new(&image, Seeds::ALL).unwrap();
    let options = MatchOptions {
        behaviour: true,
        sweep: false,
    };
    signatures::match_image(&db, packs, options)
        .unwrap()
        .into_iter()
        .filter_map(|m| {
            let ((p, e), how) = m.named?;
            let exact = matches!(how, How::Exact);
            Some((m.entry, p, packs[p].functions[e].name.clone(), exact))
        })
        .collect()
}

#[test]
fn of_one_librarys_packs_the_binarys_build_is_matched() {
    // Two versions of one library: the binary holds the build whose
    // unique identities it has most of, gcc's, and the clang build's
    // entries only compete with its own. Pack indices stay the caller's.
    let gcc = pack(&["sigs-gcc.a"], "gcc");
    let clang = signatures::make(
        &[fixture("sigs-clang.o")],
        &MakeOptions {
            version: "2".into(),
            ..options("clang")
        },
    )
    .unwrap();
    let alone: Vec<_> = named_hi(std::slice::from_ref(&gcc))
        .into_iter()
        .map(|(at, _, name, exact)| (at, 1, name, exact))
        .collect();
    assert!(
        alone
            .iter()
            .any(|(_, _, name, exact)| name == "stpcpy" && *exact),
        "{alone:?}"
    );
    assert_eq!(named_hi(&[clang, gcc]), alone);
}

#[test]
fn a_rust_pack_of_another_toolchain_names_by_identity_only() {
    // A pack whose build a rustc made, matched against a binary that
    // names no rustc (no `/rustc/COMMIT/` source path): a function a
    // version moved runs alike under its old name, so only identities
    // name.
    let rust = signatures::make(
        &[fixture("sigs-gcc.a")],
        &MakeOptions {
            toolchain: Some("rustc 1.0.0 (a59de37e9 2015-05-13)".into()),
            ..options("gcc")
        },
    )
    .unwrap();
    let plain = pack(&["sigs-gcc.a"], "gcc");
    let named = named_hi(std::slice::from_ref(&plain));
    assert!(named.iter().any(|(.., exact)| !exact), "{named:?}");
    let exact: Vec<_> = named.into_iter().filter(|(.., exact)| *exact).collect();
    assert_eq!(named_hi(std::slice::from_ref(&rust)), exact);
    // The behaviour match is listed, saying which pack's toolchain.
    let (_, data) = fixture("sigs-gcc-hi.elf");
    let image = Image::parse(&data).unwrap();
    let db = Database::new(&image, Seeds::ALL).unwrap();
    let options = MatchOptions {
        behaviour: true,
        sweep: false,
    };
    let matches = signatures::match_image(&db, std::slice::from_ref(&rust), options).unwrap();
    let strcpy = image
        .symbols
        .iter()
        .find(|s| s.name == "strcpy")
        .unwrap()
        .address;
    let m = matches.iter().find(|m| m.entry == strcpy).unwrap();
    assert!(m.named.is_none());
    assert!(
        m.candidates
            .iter()
            .any(|key| rust.functions[key.1].name == "strcpy"),
        "{m:?}"
    );
    assert!(
        m.why
            .as_deref()
            .is_some_and(|why| why.contains("sigs 1") && why.contains("rustc a59de37e9")),
        "{m:?}"
    );
}

/// The functions of `coff-x86_64.map` (link's map of coff-x86_64.exe), by
/// address: its public and static symbols flagged `f`.
fn map_functions() -> BTreeMap<u64, Vec<String>> {
    let (_, data) = fixture("coff-x86_64.map");
    let text = String::from_utf8(data).unwrap();
    let mut functions: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let [_, name, address, "f", ..] = fields[..]
            && let Ok(address) = u64::from_str_radix(address, 16)
        {
            functions.entry(address).or_default().push(name.to_owned());
        }
    }
    functions
}

#[test]
fn coff_libraries_make_windows_packs_that_name_programs() {
    let pack = pack(&["coff-x86_64.lib"], "msvc");
    assert_eq!(
        (
            pack.header.target.os.as_str(),
            pack.header.target.env.as_str()
        ),
        ("windows", "msvc")
    );
    // Every function of the two objects, once: the COMDAT both define is
    // one entry, of the first object; the alternate name is an alias.
    let entries: Vec<&str> = pack.functions.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        entries,
        [
            "?twice@@YAHH@Z",
            "bump",
            "call_import",
            "classify",
            "default_hook",
            "guarded_store",
            "use_a",
            "use_b",
            "weigh"
        ]
    );
    assert_eq!(entry(&pack, "?twice@@YAHH@Z").object, "coff-b.obj");
    assert_eq!(entry(&pack, "default_hook").aliases, ["hook"]);
    // An import library has no code to make a pack of.
    let error = signatures::make(&[fixture("coff-imports.lib")], &options("x")).unwrap_err();
    assert!(error.contains("import library"), "{error}");
    // The program linked from the library (by link, not binbun) named
    // from the pack, without its map: every name right.
    let truth = map_functions();
    let (_, data) = fixture("coff-x86_64.exe");
    let image = Image::parse(&data).unwrap();
    assert!(image.symbols.is_empty(), "the program carries no names");
    let db = Database::new(&image, Seeds::ALL).unwrap();
    let options = MatchOptions {
        behaviour: true,
        sweep: false,
    };
    let matches = signatures::match_image(&db, std::slice::from_ref(&pack), options).unwrap();
    let mut named = Vec::new();
    for m in &matches {
        let Some((key, how)) = &m.named else { continue };
        let given = &pack.functions[key.1];
        let answer = truth.get(&m.entry).cloned().unwrap_or_default();
        assert!(
            answer.contains(&given.name),
            "{:#x} named {} ({how:?}), is {answer:?}",
            m.entry,
            given.name
        );
        named.push(given.name.as_str());
    }
    // Those calling an import or through `__ImageBase`'s jump table are
    // named as the others are.
    for name in ["classify", "weigh", "?twice@@YAHH@Z"] {
        assert!(named.contains(&name), "{name} not named: {named:?}");
    }
    // The one using a thread-local fits its own recording alone, but is
    // trivial and undeclared (no prototype), which no library code here
    // calls: listed with that one candidate, not named.
    let guarded = truth
        .iter()
        .find(|(_, names)| names.iter().any(|n| n == "guarded_store"))
        .map(|(&address, _)| address)
        .unwrap();
    let m = matches.iter().find(|m| m.entry == guarded).unwrap();
    assert!(m.named.is_none(), "{m:?}");
    let candidates: Vec<&str> = m
        .candidates
        .iter()
        .map(|key| pack.functions[key.1].name.as_str())
        .collect();
    assert_eq!(candidates, ["guarded_store"], "{m:?}");
    assert!(
        m.why
            .as_deref()
            .is_some_and(|why| why.contains("the library does not declare")),
        "{m:?}"
    );
}
