//! `binbun sig make`'s provenance (`--url`, shown by `sig show`) and
//! `binbun sig eval` on the `sigs.c` fixtures (`scripts/build-fixtures.sh`):
//! a case of the same build as the pack meets the targets; one whose pack
//! is another compiler's, held to the same toolchain's targets, misses
//! recall and fails; a class with no targets is refused.
//! Packs are written zstd-compressed, or plain with `--plain`, and read
//! alike either way.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// A fresh directory for `test` under Cargo's scratch directory.
fn scratch(test: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sig-{test}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn binbun(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_binbun"))
        .args(args)
        .output()
        .unwrap()
}

/// A pack of `input` (build `build`) written to `pack`: plain if it is
/// named `.jsonl`.
fn make(input: &str, build: &str, pack: &Path) {
    let input = fixture(input);
    let mut args = vec![
        "sig",
        "make",
        "--library",
        "sigs",
        "--version",
        "1",
        "--licence",
        "MIT",
        "--source",
        "sigs.c",
        "--sha256",
        "00",
        "--url",
        "https://example.org/sigs.c",
        "--build",
        build,
        "--toolchain",
        "cc 1",
        "--flags",
        "-O2",
        &input,
        "-o",
        pack.to_str().unwrap(),
    ];
    if pack
        .extension()
        .is_some_and(|extension| extension == "jsonl")
    {
        args.push("--plain");
    }
    let output = binbun(&args);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn a_pack_records_and_shows_its_provenance() {
    let dir = scratch("provenance");
    let pack = dir.join("sigs.jsonl.zst");
    make("sigs-gcc.a", "gcc", &pack);
    let output = binbun(&["sig", "show", pack.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[1],
        "# source: sigs.c <https://example.org/sigs.c> sha256:00"
    );
    assert!(
        lines[2].starts_with("# build gcc: cc 1; flags -O2; sigs-gcc.a sha256:"),
        "{text}"
    );
    assert!(lines[3].starts_with("# made by binbun "), "{text}");
    // A URL describes a source.
    let output = binbun(&[
        "sig",
        "make",
        "--library",
        "sigs",
        "--version",
        "1",
        "--licence",
        "MIT",
        "--url",
        "https://example.org/sigs.c",
        &fixture("sigs-gcc.a"),
        "-o",
        dir.join("no.jsonl").to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(!dir.join("no.jsonl").exists());
}

#[test]
fn eval_holds_cases_to_their_class_targets() {
    let dir = scratch("eval");
    let shipped = dir.join("shipped");
    std::fs::create_dir_all(&shipped).unwrap();
    make("sigs-gcc.a", "gcc", &shipped.join("sigs-gcc.jsonl.zst"));
    make("sigs-clang.o", "clang", &dir.join("sigs-clang.jsonl"));
    // sigs.c and sigs-wrap.c, the archive's objects, linked as they are:
    // every function named (in a program of sigs.c alone, a forwarder
    // and its callee are left unnamed, so recall is under 95%).
    let program = fixture("sigs-wrap-gcc.elf");
    let cases = dir.join("cases");
    std::fs::write(
        &cases,
        format!("# the same build as the shipped pack\nhi same shipped {program} {program}\n"),
    )
    .unwrap();
    let eval = |cases: &Path| {
        binbun(&[
            "sig",
            "eval",
            cases.to_str().unwrap(),
            "--packs",
            shipped.to_str().unwrap(),
        ])
    };
    let output = eval(&cases);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(output.status.success(), "{output:?}");
    let row = text.lines().find(|l| l.starts_with("hi ")).unwrap();
    let cells: Vec<&str> = row.split_whitespace().collect();
    // case, class, packs, named, matches, mismatch, precision, matchable,
    // recall, target, seconds, verdict.
    assert_eq!(&cells[..3], ["hi", "same", "shipped"], "{text}");
    assert_eq!(cells[3], cells[4], "{text}");
    assert_eq!(cells[5], "0", "{text}");
    assert_eq!(cells[6], "100.00%", "{text}");
    assert_eq!(cells[9], "95%", "{text}");
    assert_eq!(cells[11], "met", "{text}");
    assert!(text.contains("\n# same ("), "{text}");
    assert!(text.ends_with("# every target met (1 cases)\n"), "{text}");

    // Another compiler's pack held to the same toolchain's recall: the
    // table is the error.
    std::fs::write(
        &cases,
        format!("other same sigs-clang.jsonl {program} {program}\n"),
    )
    .unwrap();
    let output = eval(&cases);
    assert!(!output.status.success());
    let text = String::from_utf8(output.stderr).unwrap();
    let row = text.lines().find(|l| l.starts_with("other ")).unwrap();
    assert!(row.contains("one build"), "{text}");
    assert!(row.contains("MISSED: recall"), "{text}");
    assert!(text.ends_with("# 1 of 1 cases missed a target\n"), "{text}");

    // A class with no targets is refused, naming it.
    std::fs::write(&cases, format!("x easy shipped {program} {program}\n")).unwrap();
    let output = eval(&cases);
    assert!(!output.status.success());
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(
        text.contains("easy") && !text.contains("# sig eval"),
        "{text}"
    );
}

#[test]
fn a_pack_reads_alike_compressed_and_plain() {
    let dir = scratch("compressed");
    let (compressed, plain) = (dir.join("sigs.jsonl.zst"), dir.join("sigs.jsonl"));
    make("sigs-gcc.a", "gcc", &compressed);
    make("sigs-gcc.a", "gcc", &plain);
    let (compressed_bytes, plain_bytes) = (
        std::fs::read(&compressed).unwrap(),
        std::fs::read(&plain).unwrap(),
    );
    assert!(compressed_bytes.len() < plain_bytes.len() / 4);
    assert_eq!(
        binbun_sigpack::pack::text(compressed_bytes)
            .unwrap()
            .as_bytes(),
        plain_bytes
    );
    let program = fixture("sigs-wrap-gcc.elf");
    let run = |args: &[&str]| {
        let output = binbun(args);
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    // The summary's last part is the time it took, which differs run to
    // run: everything before it must be the same.
    let untimed = |text: String| {
        text.lines()
            .map(|line| match line.rsplit_once("; ") {
                Some((rest, time)) if line.starts_with('#') && time.ends_with(" s") => rest,
                _ => line,
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let matched = |pack: &Path| {
        untimed(run(&[
            "sig",
            "match",
            &program,
            "--pack",
            pack.to_str().unwrap(),
        ]))
    };
    let names = matched(&compressed);
    assert!(names.contains(" exact"), "{names}");
    assert_eq!(names, matched(&plain));
    let show = |pack: &Path| run(&["sig", "show", pack.to_str().unwrap()]);
    assert_eq!(show(&compressed), show(&plain));
    // A second build added to the compressed pack, read compressed.
    let output = binbun(&[
        "sig",
        "make",
        "--library",
        "sigs",
        "--version",
        "1",
        "--licence",
        "MIT",
        "--build",
        "clang",
        "--add-to",
        compressed.to_str().unwrap(),
        &fixture("sigs-clang.o"),
        "-o",
        compressed.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{output:?}");
    assert!(show(&compressed).contains("# build clang"));
    // The file's name says which it is.
    let misnamed = dir.join("misnamed.jsonl");
    let output = binbun(&[
        "sig",
        "make",
        "--library",
        "sigs",
        "--version",
        "1",
        "--licence",
        "MIT",
        &fixture("sigs-gcc.a"),
        "-o",
        misnamed.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(!misnamed.exists());
}
