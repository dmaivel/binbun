#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]
//! A project is written by one session at a time: a second writer (in
//! another process, or a session of this one while the first is open) is
//! refused, readers are not; and a share's log opens only on the bytes it
//! is bound to.

mod common;

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use binbun_session::identity::Identity;
use binbun_session::journal::{Authority, Body, Head, Of, PublicKey, Value, Verdict};
use binbun_session::project::{Bundle, Key, Project};
use binbun_session::{Options, Session, Stage, Waited};
use common::Scratch;

/// The fixture.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf")
}

/// The identities' directory of these tests, never the user's.
fn identities() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("identity")
}

/// A session on `binary`, its project in directory `project`.
fn open(binary: &Path, project: &Path) -> Session {
    Session::open(
        binary,
        Options {
            project: Some(project.to_owned()),
            warm: false,
            identity: Some(identities()),
            ..Options::default()
        },
    )
    .unwrap()
}

/// Why `session` stopped before reading its project, if it did.
fn refused(session: &Session) -> Option<String> {
    match session.wait(Stage::Analysed, None) {
        Waited::Reached(_) => None,
        Waited::Stopped { failure, .. } => Some(failure.unwrap_or_default()),
        Waited::TimedOut(stage) => panic!("timed out at {stage:?}"),
    }
}

/// The project's lock file opened as another process would open it.
fn another(project: &Path) -> File {
    fs::create_dir_all(project.join("collab")).unwrap();
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(project.join("collab").join("lock"))
        .unwrap()
}

#[test]
fn a_second_writer_is_refused_and_a_reader_is_not() {
    let dir = Scratch::new("held-writer");
    let binary = dir.join("program");
    fs::copy(fixture(), &binary).unwrap();
    let project = dir.join("project");
    // Held by another process: refused, saying which project.
    let other = another(&project);
    other.try_lock().unwrap();
    let failure = refused(&open(&binary, &project)).unwrap();
    assert!(
        failure.contains(&project.display().to_string()),
        "{failure}"
    );
    other.unlock().unwrap();
    // Held by a session: no other writer takes it.
    let session = open(&binary, &project);
    assert_eq!(refused(&session), None);
    session.rename_function(0x1190, Some("mine")).unwrap();
    assert!(another(&project).try_lock().is_err());
    // Read meanwhile: exported, and what may be brought listed (read
    // through the session writing it, never by a second journal).
    let key = Key::of_file(&binary).unwrap();
    let bundle = Bundle::of(&Project::new(&project), &key).unwrap();
    assert!(
        bundle
            .logs()
            .iter()
            .any(|(path, _)| path.starts_with("log/chains/"))
    );
    let identity = Identity::load_or_create(&identities()).unwrap();
    let mine = Value::Text(Some("mine".to_owned()));
    assert!(
        session
            .bringable_from(&Project::new(&project), &identity)
            .unwrap()
            .iter()
            .any(|brought| brought.value == mine)
    );
    // Read from its log alone, it is held: refused at once.
    let asked = Instant::now();
    assert!(Project::new(&project).bringable(&identity).is_err());
    assert!(asked.elapsed() < Duration::from_secs(2));
    // A session that follows it holds it on, past the first's end.
    let next = session.reanalysed().unwrap();
    drop(session);
    assert!(another(&project).try_lock().is_err());
    // Let go when the last is dropped, whatever its worker still does.
    drop(next);
    assert!(another(&project).try_lock().is_ok());
}

#[test]
fn a_second_open_in_this_process_is_refused_at_once_and_a_closing_one_waited_for() {
    let dir = Scratch::new("held-here");
    let binary = dir.join("program");
    fs::copy(fixture(), &binary).unwrap();
    let project = dir.join("project");
    let session = open(&binary, &project);
    assert_eq!(refused(&session), None);
    // Open here: refused at once, not after the wait for one closing.
    let asked = Instant::now();
    let failure = refused(&open(&binary, &project)).unwrap();
    assert!(failure.contains("already open in this binbun"), "{failure}");
    assert!(asked.elapsed() < Duration::from_secs(5));
    // Closed on another thread, opened again at once: taken once let go.
    let closer = std::thread::spawn(move || session.close());
    std::thread::sleep(Duration::from_millis(50));
    let again = open(&binary, &project);
    assert_eq!(refused(&again), None);
    closer.join().unwrap();
    // Let go of by its holder while another thread holds it a moment
    // longer: opened again at once, taken once that thread lets go.
    let session = Arc::new(again);
    let lingering = Arc::clone(&session);
    let late = Duration::from_millis(300);
    let holder = std::thread::spawn(move || {
        std::thread::sleep(late);
        drop(lingering);
    });
    session.closing();
    drop(session);
    let asked = Instant::now();
    assert_eq!(refused(&open(&binary, &project)), None);
    assert!(asked.elapsed() >= late / 2);
    holder.join().unwrap();
}

/// Admits everything.
struct Everyone;

impl Authority for Everyone {
    fn admit(&self, _: PublicKey, _: u64, _: &Head, _: &Body) -> Verdict {
        Verdict::Admit
    }

    fn knows(&self, _: PublicKey) -> bool {
        true
    }

    fn grant(&self, _: PublicKey) -> Option<u64> {
        Some(1)
    }

    fn reader(&self) -> bool {
        true
    }
}

#[test]
fn a_shares_log_opens_only_on_the_bytes_it_is_bound_to() {
    let dir = Scratch::new("held-bound");
    let binary = dir.join("program");
    fs::copy(fixture(), &binary).unwrap();
    let project = dir.join("project");
    let session = open(&binary, &project);
    assert_eq!(refused(&session), None);
    session.attach(Some(Arc::new(Everyone)));
    let of = Of::Binary {
        sha256: session.file_sha256().unwrap(),
        slice: None,
    };
    session.share([5; 32], of, &BTreeMap::new()).unwrap();
    session.close();
    // The same bytes: opened.
    let again = open(&binary, &project);
    assert_eq!(refused(&again), None);
    again.close();
    // Other bytes (one more) given the same project: not opened.
    let other = dir.join("other");
    fs::copy(fixture(), &other).unwrap();
    OpenOptions::new()
        .append(true)
        .open(&other)
        .unwrap()
        .write_all(&[0])
        .unwrap();
    assert!(refused(&open(&other, &project)).is_some());
}

#[test]
fn a_slices_project_is_exported_only_as_the_container_it_is_of() {
    let dir = Scratch::new("held-universal");
    let root = dir.join("projects");
    // Two containers holding the same slices' bytes: the second has one
    // byte more after them.
    let first = dir.join("first");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/exceptions-universal.macho"),
        &first,
    )
    .unwrap();
    let second = dir.join("second");
    let mut bytes = fs::read(&first).unwrap();
    bytes.push(0);
    fs::write(&second, &bytes).unwrap();
    let (one, two) = (
        Key::of_file(&first).unwrap(),
        Key::of_file(&second).unwrap(),
    );
    assert_eq!(one.sha256(), two.sha256());
    assert_ne!(one.opened(), two.opened());
    // A project edited with the first open.
    let session = Session::open(
        &first,
        Options {
            projects: Some(root),
            warm: false,
            identity: Some(identities()),
            ..Options::default()
        },
    )
    .unwrap();
    assert_eq!(refused(&session), None);
    session.comment(0x1000, Some("first")).unwrap();
    let project = session.project().unwrap().clone();
    let opened = session.key().unwrap().clone();
    session.close();
    // Exported as the first, by the session's key or the file's: taken.
    assert!(Bundle::of(&project, &opened).is_ok());
    assert!(Bundle::of(&project, &one).is_ok());
    // As the second, the same slice's key, or by a key not read from a
    // file (which file it is is not known): refused.
    assert!(Bundle::of(&project, &two).is_err());
    assert!(Bundle::of(&project, &Key::new(&[], "first")).is_err());
}
