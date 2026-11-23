//! `binbun eval`'s `Lifted` and `L1` columns, on the checked-in fixtures.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::process::Command;

fn path(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// `binbun eval` writes the lifting columns: shares for lifted code, `-`
/// where the machine's code is not lifted; then, last, the import thunks.
#[test]
fn eval_shows_lifted_and_l1_columns() {
    let output = Command::new(env!("CARGO_BIN_EXE_binbun"))
        .args([
            "eval",
            &path("dozen-aarch64.elf"),
            &path("program-i686.exe"),
            &path("resolve-aarch64.elf"),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        lines[0].ends_with("| Lifted | L1 (at most 5000 functions, evenly by address) | Thunks |"),
        "{text}"
    );
    assert!(lines[2].starts_with("| dozen-aarch64.elf |"), "{text}");
    assert!(lines[2].ends_with("| 100.0% | 100.0% | 0 |"), "{text}");
    // MinGW's import thunks (`jmp [__imp_x]`) are counted where nothing
    // is lifted.
    assert!(lines[3].ends_with("| - | - | 31 |"), "{text}");
    // The fixture's two PLT stubs, exit's and puts'.
    assert!(lines[4].ends_with("| 2 |"), "{text}");
    // Every row has as many cells as the header.
    let cells = |line: &str| line.matches('|').count();
    assert!(
        lines.iter().all(|line| cells(line) == cells(lines[0])),
        "{text}"
    );
}
