#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! No test of this crate writes binbun's real directories (the user's
//! identity, settings, projects, state): every other test binary of the
//! crate runs again here with the variables binbun's folders are found
//! under on any platform (`HOME`, and Windows' `USERPROFILE`, `APPDATA`
//! and `LOCALAPPDATA`) an empty directory of its own, and the overrides
//! (`BINBUN_HOME`, the XDG variables) unset, so that whatever a test
//! writes where binbun keeps the user's files lands there instead. It
//! must stay empty.
//!
//! The binaries are the newest built beside this one (`cargo test`
//! builds every test target of the crate before running any).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

/// The variables binbun's folders are found under, on any platform.
const BASES: [&str; 4] = ["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"];

/// The variables that override them.
const OVERRIDES: [&str; 5] = [
    "BINBUN_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
];

/// This crate's test targets but this one: each one's binary name, and
/// the source file its dependency file names.
fn targets() -> Vec<(String, PathBuf)> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut targets = vec![("binbun_session".to_owned(), manifest.join("src/lib.rs"))];
    for entry in fs::read_dir(manifest.join("tests")).unwrap() {
        let path = entry.unwrap().path();
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if path.extension().is_some_and(|extension| extension == "rs") && stem != "real_dirs" {
            targets.push((stem.to_owned(), path.clone()));
        }
    }
    targets.sort();
    targets
}

/// The newest test binary in `deps` built for `name` from `source`
/// (`name-<hash>`, whose `.d` file names `source`: from the workspace's
/// root, as cargo writes the paths within it).
fn binary(deps: &Path, name: &str, source: &Path) -> Option<PathBuf> {
    let source = fs::canonicalize(source).ok()?;
    let workspace = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).ok()?;
    let relative = source.strip_prefix(&workspace).ok()?.to_str()?.to_owned();
    let mut found: Option<(SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(deps).ok()? {
        let path = entry.ok()?.path();
        let Some(file) = path.file_name().and_then(|file| file.to_str()) else {
            continue;
        };
        let Some(hash) = file
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('-'))
            .and_then(|rest| rest.strip_suffix(std::env::consts::EXE_SUFFIX))
        else {
            continue;
        };
        if hash.len() != 16 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let built_from = fs::read_to_string(path.with_extension("d")).is_ok_and(|deps| {
            deps.lines()
                .any(|line| line.starts_with(&format!("{relative}:")))
        });
        let modified = fs::metadata(&path).and_then(|meta| meta.modified()).ok()?;
        if built_from && found.as_ref().is_none_or(|(newest, _)| modified > *newest) {
            found = Some((modified, path));
        }
    }
    found.map(|(_, path)| path)
}

/// Every file and directory under `dir`, relative to it.
fn everything_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut work = vec![dir.to_owned()];
    while let Some(at) = work.pop() {
        let Ok(entries) = fs::read_dir(&at) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            found.push(path.strip_prefix(dir).unwrap().to_owned());
            if path.is_dir() {
                work.push(path);
            }
        }
    }
    found.sort();
    found
}

/// Every other test binary of this crate, run with an empty home, leaves
/// it empty: none writes the user's identity, settings, projects or
/// state.
#[test]
fn no_test_writes_the_real_config_or_data_directories() {
    let exe = std::env::current_exe().unwrap();
    let deps = exe.parent().unwrap();
    let home = Path::new(env!("CARGO_TARGET_TMPDIR")).join("real-dirs-home");
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let mut failed = Vec::new();
    // One at a time, as `cargo test` runs them.
    for (name, source) in targets() {
        let Some(binary) = binary(deps, &name, &source) else {
            panic!(
                "no test binary for {name} beside {}: run the crate's tests whole",
                exe.display()
            );
        };
        let mut command = Command::new(&binary);
        command.arg("-q");
        for variable in BASES {
            command.env(variable, &home);
        }
        for variable in OVERRIDES {
            command.env_remove(variable);
        }
        let output = command.output().unwrap();
        if !output.status.success() {
            failed.push(format!(
                "{name} ({}) failed under an empty home:\n{}{}",
                binary.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ));
        }
    }
    let written = everything_under(&home);
    assert!(
        written.is_empty(),
        "tests wrote where binbun keeps the user's files (here under {}): {written:#?}",
        home.display()
    );
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}
