#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Library signatures applied in a session on `sigs-app-gcc.elf`
//! (stripped; `exit` at 0x401360 never
//! returns, though its code ends in a return; `app_start` at 0x401380
//! ends in a jump to `fatal`, which calls
//! it and has code after the call, so recovery takes `fatal` into it),
//! with a pack made from the library's objects: the name, its
//! provenance and the type library's facts written as a change by a
//! signature; `exit` known not to return once analysed anew; a user's
//! name kept over a run; a rejection sticky across runs and undone; and
//! the journal's kinds appended (a change written before still reads).

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use binbun::signatures::{self, MakeOptions};
use binbun_session::journal::{Key, Origin, Value};
use binbun_session::signatures::{NameSource, Options as SignatureOptions};
use binbun_session::{Event, Matched, Options, Session, Stage};
use common::Scratch;

/// `exit`'s entry and `app_start`'s.
const EXIT: u64 = 0x40_1360;
const START: u64 = 0x40_1380;

fn fixture(name: &str) -> (String, Vec<u8>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    (name.to_owned(), fs::read(&path).unwrap())
}

/// A scratch directory with the program and a pack of the library's
/// objects in it.
fn scratch(name: &str) -> (Scratch, PathBuf, PathBuf) {
    let dir = Scratch::new(&format!("signatures-{name}"));
    let binary = dir.join("app");
    fs::write(&binary, fixture("sigs-app-gcc.elf").1).unwrap();
    let pack = signatures::make(
        &[fixture("sigs-gcc.a"), fixture("sigs-exit-gcc.o")],
        &MakeOptions {
            library: "sigs".into(),
            version: "1".into(),
            licence: "MIT".into(),
            build: "gcc-O2".into(),
            separators: true,
            ..MakeOptions::default()
        },
    )
    .unwrap();
    let file = dir.join("sigs.jsonl");
    fs::write(&file, pack.write().unwrap()).unwrap();
    (dir, binary, file)
}

/// A session on `binary`, its project kept in `root`, matching `pack` by
/// identity only (no background change to race the test's).
fn open(binary: &Path, root: &Path, pack: &Path) -> Session {
    Session::open(
        binary,
        Options {
            projects: Some(root.to_owned()),
            warm: false,
            identity: Some(Path::new(env!("CARGO_TARGET_TMPDIR")).join("identity")),
            signatures: SignatureOptions {
                packs: Some(vec![pack.to_owned()]),
                behaviour: false,
                ..SignatureOptions::default()
            },
            ..Options::default()
        },
    )
    .unwrap()
}

/// Waits for `stage`, failing on a failure.
fn wait_for(session: &Session, stage: Stage) {
    for event in &session.subscribe(None) {
        if let Event::Failed(message) = &event {
            panic!("{message}");
        }
        if matches!(event, Event::Stage(reached) if reached >= stage) {
            return;
        }
    }
}

#[test]
fn a_match_names_with_provenance_and_exit_stops_returning() {
    let (dir, binary, pack) = scratch("named");
    let session = open(&binary, &dir.join("projects"), &pack);
    wait_for(&session, Stage::Callers);
    let identified = session.signature(EXIT).unwrap();
    assert_eq!(identified.name, "exit");
    assert_eq!(identified.pack, "sigs-1@1");
    assert_eq!(identified.how, Matched::Exact);
    assert!(identified.no_return && !identified.rejected);
    assert_eq!(session.edits().function(EXIT), Some("exit"));
    assert_eq!(session.name_source(EXIT), Some(NameSource::Signature));
    // A function no pack names keeps binbun's name.
    assert_eq!(session.name_source(START), None);
    // Exit's fact corrects recovery: analysed anew, app_start (fatal in
    // it) stops returning.
    let returns = |s: &Session| {
        let database = s.database().unwrap();
        database
            .function(database.function_at(START).unwrap())
            .unwrap()
            .returns
    };
    assert!(returns(&session));
    assert_eq!(session.recovered_as_corrected(), Some(false));
    let next = session.reanalysed().unwrap();
    wait_for(&next, Stage::Callers);
    assert!(!returns(&next));
    next.close();
    session.close();
}

#[test]
fn a_users_name_stays_over_a_run() {
    let (dir, binary, pack) = scratch("renamed");
    let root = dir.join("projects");
    let session = open(&binary, &root, &pack);
    wait_for(&session, Stage::Callers);
    assert_eq!(session.edits().function(EXIT), Some("exit"));
    session.rename_function(EXIT, Some("bye")).unwrap();
    session.close();
    // Run again on the project: the user's name stays.
    let session = open(&binary, &root, &pack);
    wait_for(&session, Stage::Callers);
    assert_eq!(session.edits().function(EXIT), Some("bye"));
    assert_eq!(
        session.name_source(EXIT),
        Some(NameSource::Edit(Origin::User))
    );
    // The user's clearing is the user's too: a run leaves it.
    session.rename_function(EXIT, None).unwrap();
    session.close();
    let session = open(&binary, &root, &pack);
    wait_for(&session, Stage::Callers);
    assert_eq!(session.edits().function(EXIT), None);
    session.close();
}

#[test]
fn a_rejection_sticks_across_runs_until_undone() {
    let (dir, binary, pack) = scratch("rejected");
    let root = dir.join("projects");
    // Rejected, no run applies it; undone, the match is back.
    let session = open(&binary, &root, &pack);
    wait_for(&session, Stage::Callers);
    assert_eq!(session.edits().function(EXIT), Some("exit"));
    session.reject_signature(EXIT).unwrap();
    assert_eq!(session.edits().function(EXIT), None);
    assert!(session.signature(EXIT).unwrap().rejected);
    assert_eq!(session.name_source(EXIT), None);
    session.undo().unwrap();
    assert_eq!(session.edits().function(EXIT), Some("exit"));
    assert!(!session.signature(EXIT).unwrap().rejected);
    // Put back by the undo, the name is the signature's still.
    assert_eq!(session.name_source(EXIT), Some(NameSource::Signature));
    session.redo().unwrap();
    assert_eq!(session.edits().function(EXIT), None);
    session.close();
    let session = open(&binary, &root, &pack);
    wait_for(&session, Stage::Callers);
    assert_eq!(session.edits().function(EXIT), None);
    assert!(session.signature(EXIT).unwrap().rejected);
    session.close();
}

/// The journal's kinds are appended: the old ones keep their numbers in
/// the log's encoding (postcard numbers variants), so a change written
/// before the signatures' reads; the new ones come last.
#[test]
fn the_signatures_kinds_are_appended_to_the_journal() {
    let variant = |bytes: Vec<u8>| bytes[0];
    assert_eq!(variant(postcard::to_stdvec(&Origin::Agent).unwrap()), 3);
    assert_eq!(
        variant(postcard::to_stdvec(&Origin::Signature("p".into())).unwrap()),
        8
    );
    assert_eq!(variant(postcard::to_stdvec(&Key::Bounds(1)).unwrap()), 10);
    assert_eq!(variant(postcard::to_stdvec(&Key::DebugFile).unwrap()), 11);
    assert_eq!(
        variant(postcard::to_stdvec(&Key::Signature(1)).unwrap()),
        15
    );
    assert_eq!(
        variant(postcard::to_stdvec(&Value::Bounds(None)).unwrap()),
        3
    );
    assert_eq!(
        variant(postcard::to_stdvec(&Value::Signature(None)).unwrap()),
        8
    );
    // A function name's key and value as a log before held them.
    let old = [0u8, 0x80, 0x82, 0x01];
    assert_eq!(
        postcard::from_bytes::<Key>(&old).unwrap(),
        Key::FunctionName(0x4100)
    );
}
