//! A PE image's PDB beside it is taken without `--debug` when it is the
//! image's (GUID and age), by the name its `CodeView` record states or by
//! the image's own; another build's is passed over with a note; `--debug
//! none` takes none. On `tests/fixtures/driver-x86_64.sys` and its PDB,
//! copied into a directory of their own.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// A directory of its own for test `name`, empty.
fn scratch(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("beside-{name}"));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

/// `binbun ARGS`: its standard output and error.
fn binbun(args: &[&str]) -> (String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_binbun"))
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{args:?}");
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

/// The name `binbun functions` gives the function at 0x140001000
/// (`DriverEntry`), and what it says on standard error.
fn driver_entry(image: &Path) -> (String, String) {
    let (out, err) = binbun(&["functions", image.to_str().unwrap()]);
    let line = out
        .lines()
        .find(|line| line.starts_with("0x140001000 "))
        .unwrap();
    (line.split_whitespace().nth(3).unwrap_or("").to_owned(), err)
}

#[test]
fn the_pdb_beside_a_driver_names_its_functions_when_it_is_its_own() {
    let directory = scratch("names");
    let image = directory.join("driver-x86_64.sys");
    fs::copy(fixture("driver-x86_64.sys"), &image).unwrap();
    // Alone: nothing to take, nothing said.
    assert_eq!(driver_entry(&image), (String::new(), String::new()));
    // Another build's PDB under the name the record states: passed over.
    let stated = directory.join("driver-x86_64.pdb");
    fs::copy(fixture("msvc-x86_64.pdb"), &stated).unwrap();
    let (name, said) = driver_entry(&image);
    assert_eq!(name, "");
    assert!(
        said.starts_with(&format!("{}: not used: ", stated.display())),
        "{said}"
    );
    // Its own: taken, and said.
    fs::copy(fixture("driver-x86_64.pdb"), &stated).unwrap();
    let (name, said) = driver_entry(&image);
    assert_eq!(name, "DriverEntry");
    assert_eq!(
        said,
        format!(
            "{}: debug information from {}\n",
            image.display(),
            stated.display()
        )
    );
    // `--debug none`: not taken.
    let (c, _) = binbun(&[
        "decompile",
        image.to_str().unwrap(),
        "0x140001000",
        "--debug",
        "none",
    ]);
    assert!(c.contains("sub_140001000("), "{c}");
}

#[test]
fn a_pdb_renamed_with_its_image_is_found_by_the_image_s_name() {
    let directory = scratch("renamed");
    let image = directory.join("probe.sys");
    fs::copy(fixture("driver-x86_64.sys"), &image).unwrap();
    fs::copy(fixture("driver-x86_64.pdb"), directory.join("probe.pdb")).unwrap();
    assert_eq!(driver_entry(&image).0, "DriverEntry");
}
