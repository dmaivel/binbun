//! Stamps the build (`BINBUN_BUILD`, [`EngineVersion::build`]): what peers
//! compare to know they analyse alike.
//!
//! A `BINBUN_BUILD` set in the environment (a release's own stamp) is
//! taken as it is. Otherwise the build is the first 12 hexadecimal digits
//! of a BLAKE3 over the source that decides what an analysis is: this
//! crate and every workspace crate it depends on, transitively (each
//! file but their tests, benches and examples, by path then contents),
//! and `Cargo.lock`. The same source gives the same build on every
//! machine, with or without git.
//!
//! [`EngineVersion::build`]: src/journal/mod.rs

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The directories of a crate its build does not read.
const SKIPPED: [&str; 5] = ["tests", "benches", "examples", "fuzz", "target"];

fn main() {
    println!("cargo::rerun-if-env-changed=BINBUN_BUILD");
    if let Some(build) = std::env::var_os("BINBUN_BUILD").filter(|build| !build.is_empty()) {
        println!("cargo::rustc-env=BINBUN_BUILD={}", build.to_string_lossy());
        return;
    }
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let Some(crates) = manifest.parent() else {
        println!("cargo::rustc-env=BINBUN_BUILD=unknown");
        return;
    };
    let mut hasher = blake3::Hasher::new();
    for name in engine_crates(crates) {
        let dir = crates.join(&name);
        let mut files = Vec::new();
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let skipped = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_none_or(|name| name.starts_with('.') || SKIPPED.contains(&name));
            if !skipped {
                println!("cargo::rerun-if-changed={}", path.display());
                walk(&path, &mut files);
            }
        }
        files.sort();
        for file in files {
            hash_file(&mut hasher, crates, &file);
        }
    }
    if let Some(workspace) = crates.parent() {
        let lock = workspace.join("Cargo.lock");
        println!("cargo::rerun-if-changed={}", lock.display());
        hash_file(&mut hasher, workspace, &lock);
    }
    let hex = hasher.finalize().to_hex();
    let build = hex.get(..12).unwrap_or_default();
    println!("cargo::rustc-env=BINBUN_BUILD={build}");
}

/// This crate and the workspace crates it depends on, transitively: their
/// directories' names under `crates`.
fn engine_crates(crates: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut todo = vec!["binbun-session".to_owned()];
    while let Some(name) = todo.pop() {
        if !found.insert(name.clone()) {
            continue;
        }
        let Ok(text) = fs::read_to_string(crates.join(&name).join("Cargo.toml")) else {
            continue;
        };
        let Ok(manifest) = text.parse::<toml::Table>() else {
            continue;
        };
        for section in ["dependencies", "build-dependencies"] {
            if let Some(toml::Value::Table(deps)) = manifest.get(section) {
                todo.extend(deps.keys().filter(|dep| dep.starts_with("binbun")).cloned());
            }
        }
    }
    found
}

/// Every file under `path` (itself, if a file).
fn walk(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_file() {
        files.push(path.to_owned());
    } else if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            walk(&entry.path(), files);
        }
    }
}

/// Hashes `file`: its path under `root`, its length, its contents.
fn hash_file(hasher: &mut blake3::Hasher, root: &Path, file: &Path) {
    let Ok(bytes) = fs::read(file) else {
        return;
    };
    let relative = file.strip_prefix(root).unwrap_or(file);
    let name: Vec<String> = relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    hasher.update(name.join("/").as_bytes());
    hasher.update(&[0]);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
}
