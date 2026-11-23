#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The compile check of `binbun decompile --stats`.

use std::{env, fs};

use binbun_cli::compile_check;

#[test]
fn compile_check_counts_errors_and_warnings() {
    let valid = "#include \"helper.h\"\nint twice(int x) { return HELPER(x); }\n";
    let headers = [("helper.h", "#define HELPER(x) ((x) * 2)\n")];
    let verdicts = compile_check(valid, &headers).unwrap();
    if verdicts.is_empty() {
        eprintln!("neither gcc nor clang is installed: skipped");
        return;
    }
    for verdict in &verdicts {
        assert_eq!((verdict.errors, verdict.warnings), (0, 0), "{verdict:?}");
    }
    // An unused variable is a -Wall warning; an undeclared one an error.
    let warned = compile_check("int f(void) { int unused; return 0; }\n", &[]).unwrap();
    for verdict in &warned {
        assert_eq!(verdict.errors, 0, "{verdict:?}");
        assert!(verdict.warnings >= 1, "{verdict:?}");
    }
    // A warning quotes its line: a string there saying "error: " is no
    // error (python313's `"mimalloc: error: "`).
    let quoted = compile_check(
        "void g(const char *);\nvoid f(void) { int x; g(\"x: error: \" + x); }\n",
        &[],
    )
    .unwrap();
    for verdict in &quoted {
        assert_eq!(verdict.errors, 0, "{verdict:?}");
        assert!(verdict.warnings >= 1, "{verdict:?}");
    }
    let broken = compile_check("int f(void) { return missing; }\n", &[]).unwrap();
    assert_eq!(broken.len(), verdicts.len());
    for verdict in &broken {
        assert!(verdict.errors >= 1, "{verdict:?}");
    }
    // The checks leave nothing behind.
    let root = env::home_dir().unwrap().join(".cache/binbun-print-check");
    let prefix = format!("{}-", std::process::id());
    let left = fs::read_dir(&root).map_or(0, |entries| {
        entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .count()
    });
    assert_eq!(left, 0);
}
