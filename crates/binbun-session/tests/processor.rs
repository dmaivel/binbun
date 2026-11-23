#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! The processor setting: per
//! project and person, kept in the project's `private.toml` and nowhere
//! else (not the project file, the log or an export), kept across
//! reopening; a name that is no profile refused.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use binbun_session::project::{self, Bundle};
use binbun_session::{Options, Session, Stage};
use common::Scratch;

/// `tests/fixtures/program-x86_64.elf`.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf")
}

/// A session on the fixture, its project and identity in `dir`.
fn open(dir: &Path) -> Session {
    let options = Options {
        project: Some(dir.join("project")),
        identity: Some(dir.join("identity")),
        warm: false,
        ..Options::default()
    };
    let session = Session::open(fixture(), options).unwrap();
    session.wait(Stage::Callers, None);
    session
}

/// Every file under `dir` but `private.toml` holding `needle`.
fn holding(dir: &Path, needle: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut todo = vec![dir.to_owned()];
    while let Some(dir) = todo.pop() {
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                todo.push(path);
            } else if path.file_name().is_some_and(|name| name != "private.toml")
                && fs::read(&path)
                    .unwrap()
                    .windows(needle.len())
                    .any(|window| window == needle.as_bytes())
            {
                found.push(path);
            }
        }
    }
    found
}

#[test]
fn the_processor_is_kept_privately_and_never_exported() {
    let dir = Scratch::new("processor");
    let session = open(&dir);
    assert_eq!(session.processor(), None);
    assert!(session.profile().is_none());
    session.set_processor(Some("intel-gracemont")).unwrap();
    assert_eq!(session.processor().as_deref(), Some("intel-gracemont"));
    assert_eq!(session.profile().unwrap().id, "intel-gracemont");
    // Not a profile: refused, the setting unchanged.
    assert!(session.set_processor(Some("intel-pentium")).is_err());
    assert_eq!(session.processor().as_deref(), Some("intel-gracemont"));
    session.comment(0x1194, Some("shared note")).unwrap();
    session.save().unwrap();

    let project = dir.join("project");
    let private = fs::read_to_string(project.join("private.toml")).unwrap();
    assert!(
        private.contains("processor = \"intel-gracemont\""),
        "{private}"
    );
    assert_eq!(holding(&project, "intel-gracemont"), Vec::<PathBuf>::new());
    assert_ne!(holding(&project, "shared note"), Vec::<PathBuf>::new());
    let key = project::Key::of_file(&fixture()).unwrap();
    let exported = dir.join("program.binbun");
    project::export(&project::Project::new(&project), &key, &exported).unwrap();
    let bundle = Bundle::read(&exported).unwrap();
    assert!(
        bundle
            .files()
            .iter()
            .all(|(path, _)| path != "private.toml")
    );
    let bytes = fs::read(&exported).unwrap();
    assert!(
        !bytes
            .windows("intel-gracemont".len())
            .any(|window| window == b"intel-gracemont")
    );
    session.close();

    // Reopened: still set; cleared, gone from the file.
    let session = open(&dir);
    assert_eq!(session.processor().as_deref(), Some("intel-gracemont"));
    session.set_processor(None).unwrap();
    assert_eq!(session.processor(), None);
    let private = fs::read_to_string(project.join("private.toml")).unwrap();
    assert!(!private.contains("processor"), "{private}");
    session.close();
}
