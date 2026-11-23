#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Projects kept in binbun's data directory by the binary's contents: a
//! moved, renamed or copied binary finds its project, a changed one gets
//! a new one; a project exported to one file and imported into an empty
//! data directory shows its edits when the binary opens; importing never
//! replaces a project with edits unless asked to.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use binbun_session::project::{self, Bundle, Choice, Chosen, Imported};
use binbun_session::{Edits, Event, Key, Options, Session, Stage};
use common::Scratch;

/// The fixture.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf")
}

/// A fresh directory for test `name`.
fn scratch(name: &str) -> Scratch {
    Scratch::new(&format!("projects-{name}"))
}

/// A copy of the fixture at `to`, its directory made.
fn copy_fixture(to: &Path) -> PathBuf {
    fs::create_dir_all(to.parent().unwrap()).unwrap();
    fs::copy(fixture(), to).unwrap();
    to.to_owned()
}

/// A session on `binary`, its project kept in `root`, no warming.
fn open(binary: &Path, root: &Path) -> Session {
    Session::open(
        binary,
        Options {
            projects: Some(root.to_owned()),
            warm: false,
            // Never the user's identity.
            identity: Some(Path::new(env!("CARGO_TARGET_TMPDIR")).join("identity")),
            ..Options::default()
        },
    )
    .unwrap()
}

/// Waits for `stage`, failing on a failure.
fn wait_for(session: &Session, stage: Stage) {
    for event in &session.subscribe(None) {
        match event {
            Event::Stage(reached) if reached >= stage => return,
            Event::Failed(message) => panic!("{message}"),
            Event::Stage(_)
            | Event::Progress { .. }
            | Event::Changed(_)
            | Event::Document { .. }
            | Event::Unresolved(_)
            | Event::Symbols(_)
            | Event::Answer { .. }
            | Event::History(_)
            | Event::Conflicts(_)
            | Event::Thread(_)
            | Event::Mentioned(_)
            | Event::Bookmarks
            | Event::Reanalysed { .. } => {}
        }
    }
    panic!("the session stopped before {stage:?}");
}

/// `loop_sum`'s entry in the fixture.
fn loop_sum(session: &Session) -> u64 {
    let database = session.database().unwrap();
    let id = database.find_function("loop_sum").unwrap();
    database.function(id).unwrap().entry
}

/// Opens `binary` with its project in `root`, renames `loop_sum` to
/// `name` (saved as made), and closes it; its project.
fn rename(binary: &Path, root: &Path, name: &str) -> PathBuf {
    let session = open(binary, root);
    wait_for(&session, Stage::Analysed);
    session
        .rename_function(loop_sum(&session), Some(name))
        .unwrap();
    let dir = session.project().unwrap().dir().to_owned();
    session.close();
    dir
}

/// The project `binary` opens with in `root`, and its edits.
fn opened(binary: &Path, root: &Path) -> (PathBuf, Edits) {
    let session = open(binary, root);
    wait_for(&session, Stage::Image);
    let found = (session.project().unwrap().dir().to_owned(), session.edits());
    session.close();
    found
}

#[test]
fn a_moved_renamed_or_copied_binary_finds_its_project_and_a_changed_one_gets_a_new_one() {
    let dir = scratch("moved");
    let root = dir.join("data");
    let binary = copy_fixture(&dir.join("a").join("program"));
    let project = rename(&binary, &root, "summed");
    // Named by the bytes' SHA-256 and the file's name, in the root.
    let key = Key::of_file(&binary).unwrap();
    assert_eq!(project, root.join(key.dir_name()));
    assert!(
        key.dir_name().ends_with("-program") && key.dir_name().len() == 64 + 1 + 7,
        "{key:?}"
    );
    let saved = fs::read_to_string(project.join("project.toml")).unwrap();
    assert!(saved.contains("name = \"summed\""), "{saved}");
    let entry = {
        let session = open(&binary, &root);
        wait_for(&session, Stage::Analysed);
        let entry = loop_sum(&session);
        session.close();
        entry
    };

    // Moved and renamed: the same project, by its bytes.
    let moved = dir.join("b").join("renamed");
    fs::create_dir_all(moved.parent().unwrap()).unwrap();
    fs::rename(&binary, &moved).unwrap();
    let (found, edits) = opened(&moved, &root);
    assert_eq!(found, project);
    assert_eq!(edits.function(entry), Some("summed"));
    // A copy elsewhere: the same project too.
    let copy = dir.join("c").join("copy");
    fs::create_dir_all(copy.parent().unwrap()).unwrap();
    fs::copy(&moved, &copy).unwrap();
    let (found, edits) = opened(&copy, &root);
    assert_eq!(found, project);
    assert_eq!(edits.function(entry), Some("summed"));

    // One byte more: other bytes, another project, empty.
    let changed = dir.join("d").join("program");
    let mut bytes = fs::read(&copy).unwrap();
    bytes.push(0);
    fs::create_dir_all(changed.parent().unwrap()).unwrap();
    fs::write(&changed, &bytes).unwrap();
    let (found, edits) = opened(&changed, &root);
    assert_ne!(found, project);
    assert_eq!(found, root.join(Key::new(&bytes, "program").dir_name()));
    assert!(edits.is_empty(), "{edits:?}");
}

#[test]
fn an_exported_project_imported_into_an_empty_data_directory_shows_its_edits() {
    let dir = scratch("export");
    let binary = copy_fixture(&dir.join("program"));
    let first = dir.join("first");
    let project = project::Project::new(rename(&binary, &first, "summed"));
    fs::write(project.layout(), "format = 1\n").unwrap();
    fs::create_dir_all(project.states()).unwrap();
    fs::write(project.states().join("f.zero.toml"), "name = \"zero\"\n").unwrap();
    let key = Key::of_file(&binary).unwrap();
    let file = dir.join("program.binbun");
    project::export(&project, &key, &file).unwrap();

    let bundle = Bundle::read(&file).unwrap();
    assert_eq!(
        (bundle.sha256(), bundle.name()),
        (key.hex().as_str(), "program")
    );
    let paths: Vec<&str> = bundle.files().iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(paths, ["layout.toml", "project.toml", "states/f.zero.toml"]);
    let empty = dir.join("second");
    let Imported::Installed(installed) = project::import(&bundle, &empty, false).unwrap() else {
        panic!("not installed");
    };
    assert_eq!(installed.dir(), empty.join(key.dir_name()));
    for (path, _) in bundle.files() {
        assert_eq!(
            fs::read(installed.dir().join(path)).unwrap(),
            fs::read(project.dir().join(path)).unwrap(),
            "{path}"
        );
    }

    let session = open(&binary, &empty);
    wait_for(&session, Stage::Analysed);
    let sum = session
        .database()
        .unwrap()
        .find_function("loop_sum")
        .unwrap();
    let text = session.document(sum).unwrap().text.clone();
    assert!(text.contains("summed("), "{text}");
    session.close();
}

#[test]
fn importing_never_replaces_a_project_with_edits_unless_asked() {
    let dir = scratch("import");
    let binary = copy_fixture(&dir.join("program"));
    let key = Key::of_file(&binary).unwrap();
    let theirs = project::Project::new(rename(&binary, &dir.join("theirs"), "theirs"));
    let file = dir.join("theirs.binbun");
    project::export(&theirs, &key, &file).unwrap();
    let bundle = Bundle::read(&file).unwrap();

    // A project with only a layout is not the user's work: replaced.
    let root = dir.join("data");
    let mine = project::locate(&root, &key, &Choice::Any).unwrap().project;
    fs::create_dir_all(mine.dir()).unwrap();
    fs::write(mine.layout(), "format = 1\n").unwrap();
    assert!(!mine.has_edits());
    assert_eq!(
        project::import(&bundle, &root, false).unwrap(),
        Imported::Installed(mine.clone())
    );
    assert!(!mine.layout().exists(), "the old project's files are gone");

    // One with edits: kept, unless replacing is asked for.
    let ours = rename(&binary, &root, "ours");
    assert_eq!(ours, mine.dir());
    assert!(mine.has_edits());
    let before = fs::read_to_string(mine.edits()).unwrap();
    assert!(before.contains("\"ours\""), "{before}");
    assert_eq!(
        project::import(&bundle, &root, false).unwrap(),
        Imported::Exists(mine.clone())
    );
    assert_eq!(fs::read_to_string(mine.edits()).unwrap(), before);
    assert_eq!(
        project::import(&bundle, &root, true).unwrap(),
        Imported::Installed(mine.clone())
    );
    let after = fs::read_to_string(mine.edits()).unwrap();
    assert!(after.contains("\"theirs\""), "{after}");
    // Nothing left beside it from the swap: the project and its lock.
    let mut names: Vec<String> = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let lock = mine.lock();
    let lock = lock.file_name().unwrap().to_string_lossy();
    assert_eq!(names, [lock.as_ref(), key.dir_name().as_str()]);
}

#[test]
fn a_share_is_opened_by_its_name_else_the_only_project_else_the_one_used_last() {
    let dir = scratch("locate");
    let root = dir.join("data");
    let key = Key::of_file(&fixture()).unwrap();
    let at = |name: &str| root.join(name);
    // None yet: a new private one.
    let none = project::locate(&root, &key, &Choice::Any).unwrap();
    assert_eq!(
        (none.project.dir(), none.chosen),
        (at(&key.dir_name()).as_path(), Chosen::New)
    );
    // A joiner's share only: it is the one opened.
    let share = key.share_dir_name(&[0xab; 32]);
    assert_eq!(share, format!("{}@abababababababab", key.dir_name()));
    fs::create_dir_all(at(&share)).unwrap();
    let only = project::locate(&root, &key, &Choice::Any).unwrap();
    assert_eq!(
        (only.project.dir(), only.chosen),
        (at(&share).as_path(), Chosen::Only)
    );
    // A private one too, used later: the one used last, said so; the
    // share by the start of its name; the private one when asked.
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::create_dir_all(at(&key.dir_name())).unwrap();
    fs::write(at(&key.dir_name()).join("project.toml"), "").unwrap();
    let last = project::locate(&root, &key, &Choice::Any).unwrap();
    assert_eq!(last.chosen, Chosen::LastUsed);
    assert_eq!(last.project.dir(), at(&key.dir_name()));
    assert_eq!(last.all.len(), 2);
    let asked = project::locate(&root, &key, &Choice::Share("ABAB".to_owned())).unwrap();
    assert_eq!(
        (asked.project.dir(), asked.chosen),
        (at(&share).as_path(), Chosen::Asked)
    );
    let private = project::locate(&root, &key, &Choice::Private).unwrap();
    assert_eq!(private.project.dir(), at(&key.dir_name()));
    // A share with no project here for these bytes.
    assert!(project::locate(&root, &key, &Choice::Share("cd".to_owned())).is_err());
}
