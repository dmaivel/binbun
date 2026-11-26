//! Flags the architecture leaves undefined (SHRD's OF and AF for a count
//! other than 1, which AMD, Intel's P-cores and its E-cores set
//! differently) in `binbun decompile --stats`'s C, on
//! `tests/fixtures/undefined-x86_64.s`: never a constant, never folded;
//! the exact view's helpers compile, the reading view names them, and the
//! stats count them. A count of 1 defines OF: that one is computed.
//! `binbun stages` shows each undefined value's site and its inputs: all
//! of them in L1, those lowering knows as constants in L2.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::BTreeMap;
use std::process::Command;

/// Each function's stats line and C, as `binbun decompile --stats` prints
/// the fixture in `view`.
fn decompiled(view: &str) -> BTreeMap<String, (String, String)> {
    let path = format!(
        "{}/../../tests/fixtures/undefined-x86_64.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_binbun"))
        .args(["decompile", &path, "--stats", "--view", view])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    let mut functions = BTreeMap::new();
    let mut current: Option<(String, String, String)> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("/* 0x")
            && let Some((name, stats)) = rest
                .split_once(' ')
                .and_then(|(_, rest)| rest.split_once(": "))
        {
            if let Some((name, stats, c)) = current.take() {
                functions.insert(name, (stats, c));
            }
            current = Some((name.to_owned(), stats.to_owned(), String::new()));
        } else if let Some((_, _, c)) = &mut current
            && !line.trim().is_empty()
        {
            c.push_str(line.trim());
            c.push('\n');
        }
    }
    if let Some((name, stats, c)) = current {
        functions.insert(name, (stats, c));
    }
    functions
}

/// The stats of `name` and its C, each line trimmed (empty ones dropped).
fn function<'a>(
    functions: &'a BTreeMap<String, (String, String)>,
    name: &str,
) -> (&'a str, &'a str) {
    let (stats, c) = functions
        .get(name)
        .unwrap_or_else(|| panic!("{name} not printed: {functions:?}"));
    (stats, c)
}

/// The count `processor-dependent N` of a stats line (0 if absent).
fn processor_dependent(stats: &str) -> usize {
    stats
        .split(", ")
        .find_map(|field| field.strip_prefix("processor-dependent "))
        .map_or(0, |count| count.parse().unwrap())
}

/// Every function compiles (where a compiler is installed): no errors,
/// no warnings. Not judged on Windows: the C is a Linux program's,
/// written for LP64, and Windows' `long` is 32 bits.
fn compiled(functions: &BTreeMap<String, (String, String)>) {
    if cfg!(windows) {
        return;
    }
    for (name, (stats, _)) in functions {
        for compiler in ["gcc", "clang"] {
            if let Some(at) = stats.find(&format!(", {compiler} ")) {
                assert!(
                    stats[at..].starts_with(&format!(", {compiler} 0 errors 0 warnings")),
                    "{name}: {stats}"
                );
            }
        }
    }
}

#[test]
fn the_exact_view_calls_helpers_compilers_cannot_fold() {
    let functions = decompiled("exact");
    compiled(&functions);

    // `shrd rdx, rdx, 0x1d; jo`: the branch tests the unknown, both arms
    // kept.
    let (stats, c) = function(&functions, "shrd_jo");
    assert_eq!(processor_dependent(stats), 1, "{stats}");
    assert!(
        c.contains("if (!binbun_undefined_bool())\nreturn 2;\nreturn 1;\n"),
        "{c}"
    );

    let (stats, c) = function(&functions, "shrd_seto");
    assert_eq!(processor_dependent(stats), 1, "{stats}");
    assert!(c.contains("return binbun_undefined_bool();\n"), "{c}");

    // LAHF: AF is bit 4 of AH.
    let (stats, c) = function(&functions, "shrd_lahf");
    assert_eq!(processor_dependent(stats), 1, "{stats}");
    assert!(c.contains("(binbun_undefined_bool() << 4)"), "{c}");

    // Each SETO its own call: never one value for both.
    let (stats, c) = function(&functions, "two_shrds");
    assert_eq!(processor_dependent(stats), 2, "{stats}");
    assert_eq!(c.matches("binbun_undefined_bool()").count(), 2, "{c}");

    let (stats, _) = function(&functions, "_start");
    assert_eq!(processor_dependent(stats), 0, "{stats}");

    // A count of 1 defines OF: CMOVO takes 0xBEEF, as the processor does.
    let (stats, c) = function(&functions, "shrd_by_one");
    assert_eq!(processor_dependent(stats), 0, "{stats}");
    assert!(c.contains("return 0xbeef;\n"), "{c}");
    assert!(!c.contains("binbun_undefined"), "{c}");

    // A count of 29 on a known input: OF still undefined.
    let (stats, c) = function(&functions, "shrd_jo_known");
    assert_eq!(processor_dependent(stats), 1, "{stats}");
    assert!(
        c.contains("if (!binbun_undefined_bool())\nreturn 2;\nreturn 1;\n"),
        "{c}"
    );
}

#[test]
fn the_reading_view_names_what_the_instruction_leaves_undefined() {
    let functions = decompiled("reading");
    compiled(&functions);

    let (stats, c) = function(&functions, "shrd_jo");
    assert_eq!(processor_dependent(stats), 1, "{stats}");
    assert!(
        c.contains(
            "bool _OF_undefined = binbun_undefined_bool(); /* shrd rdx, rdx, 0x1d at 0x20116a leaves OF undefined: processors differ */\n"
        ),
        "{c}"
    );
    assert!(
        c.contains("if (!_OF_undefined)\nreturn 2;\nreturn 1;\n"),
        "{c}"
    );

    let (_, c) = function(&functions, "shrd_seto");
    assert!(c.contains("return _OF_undefined;\n"), "{c}");

    let (_, c) = function(&functions, "shrd_lahf");
    assert!(
        c.contains("bool _AF_undefined = binbun_undefined_bool(); /* shrd rax, rsi, 0x5 at 0x20118f leaves AF undefined: processors differ */\n"),
        "{c}"
    );
    assert!(c.contains("(_AF_undefined << 4)"), "{c}");

    // A name per instruction.
    let (stats, c) = function(&functions, "two_shrds");
    assert_eq!(processor_dependent(stats), 2, "{stats}");
    for (name, shift, address) in [
        ("_OF_undefined", "0x3", "0x201199"),
        ("_OF_undefined_2", "0x5", "0x2011a1"),
    ] {
        assert!(
            c.contains(&format!(
                "bool {name} = binbun_undefined_bool(); /* shrd rdi, rsi, {shift} at {address} leaves OF undefined: processors differ */\n"
            )),
            "{c}"
        );
    }

    let (stats, c) = function(&functions, "shrd_by_one");
    assert_eq!(processor_dependent(stats), 0, "{stats}");
    assert!(c.contains("return 0xbeef;\n"), "{c}");
    assert!(!c.contains("_OF_undefined"), "{c}");

    let (stats, c) = function(&functions, "shrd_jo_known");
    assert_eq!(processor_dependent(stats), 1, "{stats}");
    assert!(
        c.contains(
            "bool _OF_undefined = binbun_undefined_bool(); /* shrd rdx, rdx, 0x1d at 0x2011d5 leaves OF undefined: processors differ */\n"
        ),
        "{c}"
    );
    assert!(
        c.contains("if (!_OF_undefined)\nreturn 2;\nreturn 1;\n"),
        "{c}"
    );
}

/// Stage `stage` of the fixture's function `name`, as `binbun stages`
/// prints it.
fn stage(name: &str, stage: &str) -> String {
    let path = format!(
        "{}/../../tests/fixtures/undefined-x86_64.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_binbun"))
        .args(["stages", &path, name, "--stage", stage])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn stages_show_each_undefined_values_site_and_inputs() {
    // L1: the site, with every input (dst, src, count, old, defined.dst,
    // defined.cf) a value.
    let lifting = stage("shrd_jo", "lifting");
    let line = lifting
        .lines()
        .find(|line| line.contains("undefined @shrd.of("))
        .unwrap_or_else(|| panic!("{lifting}"));
    let inputs = line.split_once("@shrd.of(").unwrap().1;
    let inputs: Vec<&str> = inputs.split_once(')').unwrap().0.split(", ").collect();
    assert_eq!(inputs.len(), 6, "{line}");
    assert!(
        inputs
            .iter()
            .all(|input| input.starts_with('v') && input[1..].bytes().all(|b| b.is_ascii_digit())),
        "{line}"
    );
    assert!(lifting.contains("undefined @shrd.af("), "{lifting}");

    // L2: the count is a constant; rdx and the flags are not known, so
    // not kept (an input is no use of its value: the C is the same).
    let lowering = stage("shrd_jo", "lowering");
    assert!(
        lowering.contains(
            "undefined:1 @shrd.of(not_kept:64, not_kept:64, 0x1d:8, not_kept:1, not_kept:64, not_kept:1)"
        ),
        "{lowering}"
    );
    // With rdx known (0x8f, the post's input), everything but the old OF.
    let lowering = stage("shrd_jo_known", "lowering");
    assert!(
        lowering.contains(
            "undefined:1 @shrd.of(0x8f:64, 0x8f:64, 0x1d:8, not_kept:1, 0x47800000000:64, 0x0:1)"
        ),
        "{lowering}"
    );
}
