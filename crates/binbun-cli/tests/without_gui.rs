//! The root workspace's `binbun`, built without the GUI: asked for the
//! GUI (no command, or a file alone) it fails, saying it was built
//! without it, while its commands run.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::process::{Command, Output};

fn binbun(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_binbun"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn asked_for_the_gui_it_says_it_was_built_without() {
    let fixture = format!(
        "{}/../../tests/fixtures/dozen-aarch64.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    for args in [&[][..], &[fixture.as_str()]] {
        let output = binbun(args);
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let said = String::from_utf8(output.stderr).unwrap();
        assert!(said.contains("built without the GUI"), "{args:?}: {said}");
    }
    // The same file with a command is the command's.
    let output = binbun(&["functions", &fixture]);
    assert!(output.status.success());
}

#[test]
fn help_prints_the_usage() {
    for flag in ["--help", "-h"] {
        let output = binbun(&[flag]);
        assert!(output.status.success(), "{flag}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .starts_with("usage:")
        );
    }
}

#[test]
fn an_unknown_flag_is_misuse_never_a_file() {
    let output = binbun(&["--nonsense"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
    let said = String::from_utf8(output.stderr).unwrap();
    assert!(
        said.contains("usage:") && !said.contains("without the GUI"),
        "{said}"
    );
}

#[test]
fn a_command_without_its_arguments_is_its_usage_error() {
    let output = binbun(&["functions"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"");
    let said = String::from_utf8(output.stderr).unwrap();
    assert!(
        said.contains("usage:") && !said.contains("without the GUI"),
        "{said}"
    );
}

#[test]
fn version_is_binbun_and_the_version() {
    for flag in ["--version", "-V"] {
        let output = binbun(&[flag]);
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("binbun {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}
