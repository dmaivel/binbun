//! Compresses the type databases (`data/*.jsonl`, each file found there)
//! with zstd into `OUT_DIR`, and lists them in `OUT_DIR/embedded.rs` for
//! `src/shipped.rs` to embed: the library carries the compressed bytes and
//! decompresses a database when it is first asked for.
//!
//! They are listed in the order a target's databases are added to its
//! library ([`ORDER`]), which decides whose a named type two of them
//! define is (the first's).
//!
//! The level is fixed, and zstd is deterministic at a level: the same
//! databases give the same bytes. A database is compressed again only when
//! its file is newer than its compressed copy (another file in `data/`,
//! such as `overrides.toml`, reruns this script but compresses nothing).

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// zstd's level. The Win32 database's 21.8 MB compress to 1.7 MB in under
/// a second (level 19: 1.5 MB in 15 s, paid on every clean build and
/// every change to a database: not worth 220 KB).
const LEVEL: i32 = 9;

/// The databases by what they declare (the file name's last part,
/// `linux-x86_64-libc.jsonl`'s `libc`), first added first: the C runtime
/// (its `struct stat`, `FILE` are those programs name; the UCRT's before
/// msvcrt.dll's others), the C++ runtime's ABI, Windows' native API,
/// system calls (syzkaller's records of the C library's names), Win32.
/// Others follow, by name.
const ORDER: [&str; 7] = [
    "libc", "ucrt", "msvcrt", "cxxabi", "native", "syscalls", "win32",
];

fn main() {
    println!("cargo::rerun-if-changed=data");
    let manifest =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let data = manifest.join("data");
    let mut names: Vec<String> = fs::read_dir(&data)
        .unwrap_or_else(|error| panic!("{}: {error}", data.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("{}: {error}", data.display()))
                .file_name()
                .into_string()
                .expect("a file name in data/ is UTF-8")
        })
        .filter(|name| {
            Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect();
    names.sort_by(|a, b| (rank(a), a).cmp(&(rank(b), b)));
    let mut list = String::from("[\n");
    for name in &names {
        let source = data.join(name);
        let compressed = out.join(format!("{name}.zst"));
        if !fresh(&compressed, &source) {
            let text =
                fs::read(&source).unwrap_or_else(|error| panic!("{}: {error}", source.display()));
            let bytes = zstd::bulk::compress(&text, LEVEL)
                .unwrap_or_else(|error| panic!("{}: {error}", source.display()));
            // Renamed into place: a build stopped while writing leaves no
            // fresh-looking partial copy.
            let part = out.join(format!("{name}.zst.part"));
            fs::write(&part, bytes)
                .and_then(|()| fs::rename(&part, &compressed))
                .unwrap_or_else(|error| panic!("{}: {error}", compressed.display()));
        }
        let _ = writeln!(
            list,
            "    ({name:?}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{name}.zst\"))),"
        );
    }
    list.push_str("]\n");
    let listing = out.join("embedded.rs");
    fs::write(&listing, list).unwrap_or_else(|error| panic!("{}: {error}", listing.display()));
}

/// Whether `compressed` exists and is not older than `source`.
fn fresh(compressed: &Path, source: &Path) -> bool {
    let modified = |path: &Path| fs::metadata(path).and_then(|metadata| metadata.modified());
    match (modified(compressed), modified(source)) {
        (Ok(compressed), Ok(source)) => compressed >= source,
        _ => false,
    }
}

/// Where database file `name` comes in [`ORDER`] (after it: not there).
fn rank(name: &str) -> usize {
    let kind = name
        .trim_end_matches(".jsonl")
        .rsplit('-')
        .next()
        .unwrap_or_default();
    ORDER
        .iter()
        .position(|known| *known == kind)
        .unwrap_or(ORDER.len())
}
