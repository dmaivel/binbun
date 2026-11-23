//! `binbun decompile FILE F1 F2 ...`: each function printed as
//! `binbun decompile FILE Fi` prints it alone, in the order given, byte
//! for byte, in both views; a function it cannot find fails it as alone.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::process::{Command, Output};

/// `binbun decompile` of the fixture with `args` after it.
fn decompile(args: &[&str]) -> Output {
    let path = format!(
        "{}/../../tests/fixtures/program-x86_64.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    Command::new(env!("CARGO_BIN_EXE_binbun"))
        .args(["decompile", &path])
        .args(args)
        .output()
        .unwrap()
}

/// What `binbun decompile` of the fixture prints with `args`.
fn printed(args: &[&str]) -> String {
    let output = decompile(args);
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn several_functions_print_as_each_alone_in_the_order_given() {
    // Not in address order (main is first there), one by address.
    let wanted = ["loop_sum", "main", "0x1190"];
    for view in ["exact", "reading"] {
        let alone: String = wanted
            .iter()
            .map(|function| printed(&[function, "--view", view]))
            .collect();
        let together = printed(&[wanted[0], wanted[1], wanted[2], "--view", view]);
        assert_eq!(together, alone, "{view}");
    }
}

#[test]
fn a_function_it_cannot_find_fails_it_as_alone() {
    let together = decompile(&["main", "no_such_function"]);
    let alone = decompile(&["no_such_function"]);
    assert!(!together.status.success() && !alone.status.success());
    assert_eq!(together.stderr, alone.stderr);
    assert!(together.stdout.is_empty(), "{together:?}");
}

/// `binbun decompile` of fixture `file`'s function `function` with `args`.
fn function_of(file: &str, function: &str, args: &[&str]) -> String {
    let path = format!("{}/../../tests/fixtures/{file}", env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(env!("CARGO_BIN_EXE_binbun"))
        .args(["decompile", &path, function])
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn plain_types_spell_64_bits_as_the_binarys_platform_does() {
    // ELF (LP64): `long`.
    let elf = function_of("program-x86_64.elf", "loop_sum", &["--types", "plain"]);
    assert!(elf.contains("int checked(long);"), "{elf}");
    assert!(elf.contains("int loop_sum(int a1)"), "{elf}");
    assert!(
        !elf.contains("int32_t") && !elf.contains("int64_t"),
        "{elf}"
    );
    // PE (LLP64): `long long`, `long` being 32 bits there.
    let pe = function_of("msvc-x86_64.exe", "measure", &["--types", "plain"]);
    assert!(
        pe.contains("unsigned long long measure(char *s, unsigned long long extra)"),
        "{pe}"
    );
    // Fixed-width by default, and as asked.
    let fixed = function_of("msvc-x86_64.exe", "measure", &[]);
    assert!(
        fixed.contains("uint64_t measure(char *s, uint64_t extra)"),
        "{fixed}"
    );
    assert_eq!(
        function_of("msvc-x86_64.exe", "measure", &["--types", "fixed"]),
        fixed
    );
    assert!(!decompile(&["loop_sum", "--types", "long"]).status.success());
}
