#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Finding an image's debug information where the conventions put it: by
//! `.gnu_debuglink` beside the image, by build ID under the debug
//! directory and in the debuginfod cache (only a file of the same build),
//! the PDB the `CodeView` record names beside the image; and nothing for
//! an image without any.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use binbun_debuginfo::info::locate::{self, Search};
use object::Object;

fn fixture(name: &str) -> PathBuf {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap();
    workspace.join("tests").join("fixtures").join(name)
}

/// A scratch directory of its own for test `name`, empty.
fn scratch(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("locate-{name}"));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

/// A search with no debug directory and no debuginfod cache.
fn nowhere(scratch: &Path) -> Search {
    Search {
        debug_directory: scratch.join("no-debug-directory"),
        debuginfod_cache: None,
    }
}

/// The fixture `name` copied alone into `directory`.
fn alone(name: &str, directory: &Path) -> (PathBuf, Vec<u8>) {
    let path = directory.join(name);
    fs::copy(fixture(name), &path).unwrap();
    (path, fs::read(fixture(name)).unwrap())
}

fn build_id(data: &[u8]) -> String {
    let id = object::File::parse(data)
        .unwrap()
        .build_id()
        .unwrap()
        .unwrap();
    id.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").unwrap();
        text
    })
}

#[test]
fn a_debuglink_beside_the_image_is_found() {
    let path = fixture("units-x86_64.elf");
    let data = fs::read(&path).unwrap();
    let found = nowhere(&scratch("debuglink")).find(&path, &data).unwrap();
    assert_eq!(found.path, fixture("units-x86_64.debug"));
    assert_eq!(found.model.units.len(), 2);
}

#[test]
fn the_build_id_directory_and_the_debuginfod_cache_are_searched() {
    let directory = scratch("build-id");
    let (path, data) = alone("units-x86_64.elf", &directory);
    let id = build_id(&data);
    let search = nowhere(&directory);
    assert!(search.find(&path, &data).is_none());

    let by_id = Search {
        debug_directory: directory.join("debug"),
        debuginfod_cache: None,
    };
    let file = directory
        .join("debug/.build-id")
        .join(&id[..2])
        .join(format!("{}.debug", &id[2..]));
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::copy(fixture("units-x86_64.debug"), &file).unwrap();
    assert_eq!(by_id.find(&path, &data).unwrap().path, file);

    let cache = Search {
        debug_directory: directory.join("no-debug-directory"),
        debuginfod_cache: Some(directory.join("cache")),
    };
    let file = directory.join("cache").join(&id).join("debuginfo");
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::copy(fixture("units-x86_64.debug"), &file).unwrap();
    assert_eq!(cache.find(&path, &data).unwrap().path, file);
}

/// A file where the build ID says, but of another build, is not taken.
#[test]
fn a_debug_file_of_another_build_is_not_taken() {
    let directory = scratch("another-build");
    let (path, data) = alone("units-x86_64.elf", &directory);
    let file = directory
        .join("cache")
        .join(build_id(&data))
        .join("debuginfo");
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::copy(fixture("program-x86_64.debug"), &file).unwrap();
    let search = Search {
        debug_directory: directory.join("no-debug-directory"),
        debuginfod_cache: Some(directory.join("cache")),
    };
    assert!(search.candidates(&path, &data).contains(&file));
    assert!(search.find(&path, &data).is_none());
}

/// The debuginfod client's record of a failed query, an empty file where
/// the download would go, is no file: not reported as another build's,
/// and no obstacle to a debug file found after it.
#[test]
fn an_empty_debuginfod_entry_is_no_file() {
    let directory = scratch("empty-entry");
    let (path, data) = alone("units-x86_64.elf", &directory);
    let id = build_id(&data);
    let empty = directory.join("cache").join(&id).join("debuginfo");
    fs::create_dir_all(empty.parent().unwrap()).unwrap();
    fs::write(&empty, b"").unwrap();
    let search = Search {
        debug_directory: directory.join("no-debug-directory"),
        debuginfod_cache: Some(directory.join("cache")),
    };
    let searched = search.search(&path, &data);
    assert!(searched.found.is_none());
    assert!(searched.passed.is_empty(), "{:?}", searched.passed);

    // An empty file first in the order (by build ID under the debug
    // directory), the cache's real file after it.
    let first = directory
        .join("debug/.build-id")
        .join(&id[..2])
        .join(format!("{}.debug", &id[2..]));
    fs::create_dir_all(first.parent().unwrap()).unwrap();
    fs::write(&first, b"").unwrap();
    fs::copy(fixture("units-x86_64.debug"), &empty).unwrap();
    let search = Search {
        debug_directory: directory.join("debug"),
        debuginfod_cache: Some(directory.join("cache")),
    };
    let searched = search.search(&path, &data);
    assert_eq!(searched.found.unwrap().path, empty);
    assert!(searched.passed.is_empty(), "{:?}", searched.passed);
}

#[test]
fn the_pdb_the_codeview_record_names_is_found_beside_the_image() {
    let path = fixture("msvc-x86_64.exe");
    let data = fs::read(&path).unwrap();
    let found = nowhere(&scratch("pdb")).find(&path, &data).unwrap();
    assert_eq!(found.path, fixture("msvc-x86_64.pdb"));
    let main = found
        .model
        .functions
        .values()
        .find(|function| function.name.as_deref() == Some("main"));
    assert!(main.is_some_and(|main| main.unit.is_some()));
}

/// Another image's PDB under the name the record states is not taken
/// (the GUID and age differ).
#[test]
fn another_images_pdb_is_not_taken() {
    let directory = scratch("another-pdb");
    let (path, data) = alone("msvc-x86_64.exe", &directory);
    fs::copy(fixture("eh-x86_64.pdb"), directory.join("msvc-x86_64.pdb")).unwrap();
    assert!(nowhere(&directory).find(&path, &data).is_none());
    assert!(locate::open(&directory.join("msvc-x86_64.pdb"), &path, &data).is_err());
    // The search says it passed it over, and why.
    let searched = nowhere(&directory).search(&path, &data);
    assert_eq!(searched.passed.len(), 1);
    assert_eq!(searched.passed[0].0, directory.join("msvc-x86_64.pdb"));
    assert!(
        searched.passed[0].1.contains("is not the image's"),
        "{}",
        searched.passed[0].1
    );
}

/// A PDB renamed with its image (`probe.sys`, `probe.pdb`) is found by
/// the image's name when none has the name the record states; one with
/// that name is tried first (after the path the record states, absolute
/// on Windows), and passed over if another build's.
#[test]
fn a_pdb_renamed_with_its_image_is_found_by_the_image_s_name() {
    let directory = scratch("renamed-pdb");
    let path = directory.join("probe.sys");
    fs::copy(fixture("driver-x86_64.sys"), &path).unwrap();
    let data = fs::read(&path).unwrap();
    let renamed = directory.join("probe.pdb");
    fs::copy(fixture("driver-x86_64.pdb"), &renamed).unwrap();
    let stated = directory.join("driver-x86_64.pdb");
    let built = PathBuf::from(r"C:\binbun\fixtures\driver-x86_64.pdb");
    let mut candidates: Vec<_> = built.is_absolute().then_some(built).into_iter().collect();
    candidates.extend([stated.clone(), renamed.clone()]);
    assert_eq!(nowhere(&directory).candidates(&path, &data), candidates);
    let searched = nowhere(&directory).search(&path, &data);
    assert_eq!(searched.found.unwrap().path, renamed);
    assert_eq!(searched.passed, []);
    fs::copy(fixture("msvc-x86_64.pdb"), &stated).unwrap();
    let searched = nowhere(&directory).search(&path, &data);
    assert_eq!(searched.found.unwrap().path, renamed);
    assert_eq!(
        searched.passed.iter().map(|(p, _)| p).collect::<Vec<_>>(),
        [&stated]
    );
}

#[test]
fn an_image_without_debug_information_has_none() {
    let path = fixture("program-x86_64.elf");
    let data = fs::read(&path).unwrap();
    assert!(nowhere(&scratch("none")).find(&path, &data).is_none());
}
