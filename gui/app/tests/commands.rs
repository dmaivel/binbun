//! The GUI's `binbun` runs the CLI's commands without opening a window
//! (these run headless), as the one `binbun` command.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::process::{Command, Output};

fn binbun(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_binbun"))
        .args(args)
        .output()
        .unwrap()
}

fn fixture(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn a_command_runs_without_the_gui() {
    let output = binbun(&["functions", &fixture("dozen-aarch64.elf")]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.lines().any(|line| line.ends_with(" leaf_sum")),
        "{text}"
    );
    let output = binbun(&["--version"]);
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("binbun {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_does_not_say_the_gui_is_missing() {
    let output = binbun(&["--help"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("binbun [FILE]"), "{text}");
    assert!(!text.contains("without the GUI"), "{text}");
}

/// Built without `collab`, the commands are built without it too.
#[cfg(not(feature = "collab"))]
#[test]
fn without_collaboration_its_commands_say_so() {
    let output = binbun(&["id"]);
    assert!(!output.status.success());
    let said = String::from_utf8(output.stderr).unwrap();
    assert!(said.contains("built without collaboration"), "{said}");
}
