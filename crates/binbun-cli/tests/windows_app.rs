//! Windows: the commands alone as the release zip lays them out
//! (`bin\binbun.exe`, the app `binbun.exe` in the folder above) start the
//! app for what opens the GUI and return at once, successfully, saying
//! nothing; without the app above them they say they were built without
//! the GUI, as anywhere else.

#![cfg(windows)]
#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A folder of its own for `name`, `bin\binbun.exe` in it (a copy of
/// the commands), and the app `binbun.exe` above it if `with_app` (a
/// copy of the commands too: started with a file, it exits).
fn layout(name: &str, with_app: bool) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("bin")).unwrap();
    let built = env!("CARGO_BIN_EXE_binbun");
    fs::copy(built, root.join("bin").join("binbun.exe")).unwrap();
    if with_app {
        fs::copy(built, root.join("binbun.exe")).unwrap();
    }
    root
}

fn binbun(root: &Path, args: &[&str]) -> Output {
    Command::new(root.join("bin").join("binbun.exe"))
        .args(args)
        .output()
        .unwrap()
}

fn fixture() -> String {
    format!(
        "{}/../../tests/fixtures/dozen-aarch64.elf",
        env!("CARGO_MANIFEST_DIR")
    )
}

#[test]
fn with_the_app_above_a_file_alone_starts_it() {
    let root = layout("windows-app-with", true);
    let fixture = fixture();
    for args in [&[][..], &[fixture.as_str()]] {
        let output = binbun(&root, args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(output.stderr.is_empty(), "{args:?}");
    }
    // `--help` leaves out that this build has no GUI; commands run here.
    let help = String::from_utf8(binbun(&root, &["--help"]).stdout).unwrap();
    assert!(!help.contains("built without the GUI"), "{help}");
    assert!(binbun(&root, &["functions", &fixture]).status.success());
}

#[test]
fn without_the_app_it_says_it_was_built_without_the_gui() {
    let root = layout("windows-app-without", false);
    let fixture = fixture();
    for args in [&[][..], &[fixture.as_str()]] {
        let output = binbun(&root, args);
        assert!(!output.status.success(), "{args:?}");
        let said = String::from_utf8(output.stderr).unwrap();
        assert!(said.contains("built without the GUI"), "{args:?}: {said}");
    }
    let help = String::from_utf8(binbun(&root, &["--help"]).stdout).unwrap();
    assert!(help.contains("built without the GUI"), "{help}");
}
