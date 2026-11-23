#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Corrections of recovery through a session: refused with the reason
//! where they cannot apply; saved; taken by a session opened again
//! ([`Session::reanalysed`]), which brings the edits made meanwhile
//! along; applied when the binary is opened again; exported with the
//! project.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use binbun_session::corrections::{Data, Unit};
use binbun_session::project::{self, Bundle, Imported};
use binbun_session::{
    Bounds, Corrections, Edits, Error, Event, Item, Key, Matched, Options, Session, Stage,
};
use common::Scratch;

/// A fresh directory for test `name`, holding a copy of the fixture
/// (`classify` called by `checked`, called by `loop_sum`).
fn scratch(name: &str) -> (Scratch, PathBuf) {
    let dir = Scratch::new(&format!("corrections-{name}"));
    let binary = dir.join("program");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf"),
        &binary,
    )
    .unwrap();
    (dir, binary)
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

/// A function made in `classify`'s padding, a word at `0x2000`, the
/// string at `0x2004` undefined, `checked` ending before its error path.
fn some() -> Corrections {
    let mut c = Corrections::default();
    c.set_bounds(0x11a3, Some(Bounds::Function { end: None }));
    c.set_bounds(0x11d0, Some(Bounds::Function { end: Some(0x11e4) }));
    c.set_item(
        0x2000,
        Some(Item::Data(Data {
            unit: Unit::Word,
            count: 2,
        })),
    );
    c.set_item(0x2004, Some(Item::Undefined { size: 9 }));
    c
}

#[test]
fn a_correction_that_cannot_apply_is_refused_and_nothing_changes() {
    let (dir, binary) = scratch("refused");
    let session = open(&binary, &dir.join("projects"));
    wait_for(&session, Stage::Analysed);
    let mut c = Corrections::default();
    c.set_item(0x1191, Some(Item::Code));
    assert_eq!(
        session.set_corrections(&c),
        Err(Error::Correction(
            "0x1191 is inside the instruction at 0x1190".to_owned()
        ))
    );
    assert!(session.corrections().is_empty());
    assert_eq!(session.recovered_as_corrected(), Some(true));
    session.close();
}

#[test]
fn corrections_are_saved_taken_by_a_new_analysis_and_applied_on_reopening() {
    let (dir, binary) = scratch("reanalysed");
    let root = dir.join("projects");
    let session = open(&binary, &root);
    wait_for(&session, Stage::Callers);
    session.set_corrections(&some()).unwrap();
    // Recorded and saved; this session's program is as it was.
    assert_eq!(session.recovered_as_corrected(), Some(false));
    assert!(session.database().unwrap().function_at(0x11a3).is_none());
    let saved = fs::read_to_string(session.project().unwrap().edits()).unwrap();
    assert!(
        saved.contains("[[item]]\naddress = \"0x2000\"\nkind = \"word\"\ncount = 2"),
        "{saved}"
    );
    assert!(
        saved.contains("[[bounds]]\nfunction = \"0x11d0\"\nend = \"0x11e4\""),
        "{saved}"
    );

    let next = session.reanalysed().unwrap();
    // An edit made meanwhile comes along.
    session.rename_function(0x11d0, Some("guarded")).unwrap();
    wait_for(&next, Stage::Callers);
    next.take_edits(&session);
    assert_eq!(next.recovered_as_corrected(), Some(true));
    assert_eq!(next.edits().function(0x11d0), Some("guarded"));
    let database = next.database().unwrap();
    assert_eq!(*database.corrections(), some());
    let made = database.function_at(0x11a3).unwrap();
    let text = next.document(made).unwrap().text.clone();
    assert!(
        text.contains("sub_11a3(") && text.contains("fail("),
        "{text}"
    );
    // `checked` calls what its end split off.
    let checked = database.function_at(0x11d0).unwrap();
    let text = next.document(checked).unwrap().text.clone();
    assert!(
        text.contains("guarded(") && text.contains("sub_11e4("),
        "{text}"
    );
    session.close();
    next.close();

    // Opened again, the binary is recovered with them.
    let again = open(&binary, &root);
    wait_for(&again, Stage::Analysed);
    assert_eq!(again.corrections(), some());
    assert_eq!(again.recovered_as_corrected(), Some(true));
    assert!(again.database().unwrap().function_at(0x11e4).is_some());
    again.close();
}

#[test]
fn a_correction_made_during_a_new_analysis_needs_another() {
    let (dir, binary) = scratch("meanwhile");
    let session = open(&binary, &dir.join("projects"));
    wait_for(&session, Stage::Analysed);
    session.set_corrections(&some()).unwrap();
    let next = session.reanalysed().unwrap();
    let mut more = some();
    more.set_bounds(0x1190, Some(Bounds::Deleted));
    session.set_corrections(&more).unwrap();
    wait_for(&next, Stage::Analysed);
    next.take_edits(&session);
    assert_eq!(next.corrections(), more);
    assert_eq!(next.recovered_as_corrected(), Some(false));
    session.close();
    next.close();
}

#[test]
fn corrections_are_exported_with_the_project() {
    let (dir, binary) = scratch("exported");
    let first = dir.join("first");
    let session = open(&binary, &first);
    wait_for(&session, Stage::Analysed);
    session.set_corrections(&some()).unwrap();
    let project = session.project().unwrap().clone();
    session.close();
    let key = Key::of_file(&binary).unwrap();
    let file = dir.join("program.binbun");
    project::export(&project, &key, &file).unwrap();
    let bundle = Bundle::read(&file).unwrap();
    let second = dir.join("second");
    let Imported::Installed(_) = project::import(&bundle, &second, false).unwrap() else {
        panic!("not installed");
    };
    let session = open(&binary, &second);
    wait_for(&session, Stage::Analysed);
    assert_eq!(session.corrections(), some());
    assert!(session.database().unwrap().function_at(0x11a3).is_some());
    session.close();
}

#[test]
fn a_project_file_reads_as_written() {
    let plain = "format = 1\n\n[[function]]\naddress = \"0x1190\"\nname = \"classify\"\n";
    let edits = Edits::parse(plain).unwrap();
    assert_eq!(edits.function(0x1190), Some("classify"));
    assert_eq!(edits.to_toml().unwrap(), plain);

    let corrected = format!(
        "{}\n\n[[item]]\naddress = \"0x2000\"\nkind = \"word\"\ncount = 2\n\n\
         [[item]]\naddress = \"0x2004\"\nkind = \"undefined\"\nsize = 9\n\n\
         [[bounds]]\nfunction = \"0x11a3\"\n\n\
         [[bounds]]\nfunction = \"0x11d0\"\nend = \"0x11e4\"\n",
        plain.trim_end()
    );
    let read = Edits::parse(&corrected).unwrap();
    assert_eq!(read.corrections(), &some());
    assert_eq!(read.to_toml().unwrap(), corrected);
    assert_eq!(read.function(0x1190), Some("classify"));

    // A library signature's match (and its correction: exit never
    // returns).
    let matched = format!(
        "{}\n\n[[signature]]\nfunction = \"0x1190\"\npack = \"sigs-1@1\"\n\
         library = \"sigs\"\nversion = \"1\"\nname = \"classify\"\nobject = \"exit.o\"\n\
         how = \"behaviour\"\nstates = 32\nruled_out = 2\nno_return = true\n",
        plain.trim_end()
    );
    let read = Edits::parse(&matched).unwrap();
    assert_eq!(read.to_toml().unwrap(), matched);
    let identified = read.signature(0x1190).unwrap();
    assert_eq!(
        identified.how,
        Matched::Behaviour {
            states: 32,
            ruled_out: 2
        }
    );
    assert!(read.corrections().no_return().contains(&0x1190));
    assert_eq!(
        Edits::parse("format = 2\n").unwrap_err(),
        "format 2 is newer than this binbun's (1)"
    );
    assert!(Edits::parse("format = 0\n").is_err());
}
