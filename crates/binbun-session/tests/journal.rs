#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! The journal through a session: groups of edits made as one change (one
//! save, one merged change event, one undo step) or dropped whole; undo
//! and redo restoring the project file byte for byte; the swap of a new
//! analysis carrying the edits made meanwhile ([`Lineage`]).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use binbun::cfg::FunctionId;
use binbun_session::journal::{Key, Origin, Value};
use binbun_session::{
    Bounds, Change, Corrections, Event, Lineage, Options, Session, Stage, Typed, View,
};

/// `tests/fixtures/{name}`.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// A fresh directory for test `name` in this process (test binaries run at
/// once over one target directory share its temporary directory).
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("journal-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Options keeping the project in `project`, no warming, signing with an
/// identity of the tests' own (never the user's).
fn options(project: &Path) -> Options {
    Options {
        project: Some(project.to_owned()),
        warm: false,
        identity: Some(Path::new(env!("CARGO_TARGET_TMPDIR")).join("identity")),
        ..Options::default()
    }
}

/// A session on the fixture (`classify` called by `checked`, called by
/// `loop_sum`), its project in `project`, its callers known.
fn open(project: &Path) -> Session {
    let session = Session::open(fixture("program-x86_64.elf"), options(project)).unwrap();
    session.wait(Stage::Callers, None);
    session
}

/// The entry of the function named `name` (the user's name, else its
/// symbol).
fn entry(session: &Session, name: &str) -> u64 {
    let database = session.database().unwrap();
    database
        .functions()
        .find(|(_, f)| session.name(f.entry).as_deref() == Some(name))
        .map(|(_, f)| f.entry)
        .unwrap()
}

/// The changes told on `events` so far.
fn changes(events: &Receiver<Event>) -> Vec<Change> {
    events
        .try_iter()
        .filter_map(|event| match event {
            Event::Changed(change) => Some((*change).clone()),
            Event::Stage(_)
            | Event::Progress { .. }
            | Event::Document { .. }
            | Event::Unresolved(_)
            | Event::Symbols(_)
            | Event::Answer { .. }
            | Event::Failed(_)
            | Event::History(_)
            | Event::Conflicts(_)
            | Event::Thread(_)
            | Event::Mentioned(_)
            | Event::Bookmarks
            | Event::Reanalysed { .. } => None,
        })
        .collect()
}

/// The project file's bytes.
fn file(session: &Session) -> Vec<u8> {
    fs::read(session.project().unwrap().edits()).unwrap_or_default()
}

/// Makes renames, comments and a prototype in `session`; the union of
/// what each changed.
fn some_edits(session: &Session) -> Change {
    let mut documents = BTreeSet::new();
    let mut listing = Vec::new();
    let mut take = |change: &Change| {
        documents.extend(change.documents.iter().copied());
        listing.extend(change.listing.iter().cloned());
    };
    for (name, new) in [
        ("classify", "sort"),
        ("checked", "guard"),
        ("loop_sum", "sum"),
    ] {
        take(
            &session
                .rename_function(entry(session, name), Some(new))
                .unwrap(),
        );
    }
    let classify = entry(session, "sort");
    for at in [classify, classify + 1] {
        take(&session.comment(at, Some("here")).unwrap());
    }
    take(
        &session
            .set_type(
                Typed::Prototype(classify),
                Some("unsigned int sort(unsigned int value)"),
            )
            .unwrap(),
    );
    listing.sort_by_key(|range| (range.start, range.end));
    let mut merged: Vec<std::ops::Range<u64>> = Vec::new();
    for range in listing {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            Some(_) | None => merged.push(range),
        }
    }
    Change {
        documents: documents.into_iter().collect(),
        listing: merged,
    }
}

#[test]
fn a_group_is_one_change_one_save_one_merged_change_event() {
    let dir = scratch("group");
    let session = open(&dir);
    let events = session.subscribe(None);
    let (saves, history) = (session.saves(), session.history().len());
    session.begin("Name things", Origin::Script("test".to_owned()));
    let expected = some_edits(&session);
    assert!(session.in_group());
    // Read and printed with them before the commit, nothing saved or told.
    assert_eq!(
        session.edits().function(entry(&session, "sort")),
        Some("sort")
    );
    assert_eq!(session.saves(), saves);
    assert_eq!(changes(&events), Vec::new());
    let made = session.commit().unwrap().unwrap();
    assert_eq!(made.label, "Name things");
    assert_eq!(made.origin, Origin::Script("test".to_owned()));
    assert_eq!(made.edits, 6);
    assert_eq!(session.saves(), saves + 1);
    assert_eq!(changes(&events), vec![expected]);
    assert_eq!(session.history().len(), history + 1);
    assert_eq!(session.history()[0], made);
    assert_eq!(session.revision().edits, 1);
    // One undo step.
    session.undo().unwrap().unwrap();
    assert!(session.edits().is_empty());
    session.close();
}

#[test]
fn a_group_inside_a_group_joins_it() {
    let dir = scratch("nested");
    let session = open(&dir);
    session.begin("Outer", Origin::User);
    session
        .rename_function(entry(&session, "classify"), Some("a"))
        .unwrap();
    session.begin("Inner", Origin::User);
    session.comment(0x1190, Some("b")).unwrap();
    assert_eq!(session.commit().unwrap(), None);
    assert!(session.in_group());
    let made = session.commit().unwrap().unwrap();
    assert_eq!((made.label.as_str(), made.edits), ("Outer", 2));
    assert!(!session.in_group());
    session.close();
}

#[test]
fn a_group_rolled_back_leaves_the_edits_and_project_file_as_they_were() {
    let dir = scratch("rollback");
    let session = open(&dir);
    session.comment(0x1190, Some("kept")).unwrap();
    let (edits, bytes, history) = (session.edits(), file(&session), session.history());
    let saves = session.saves();
    let checked = session
        .database()
        .unwrap()
        .function_at(entry(&session, "checked"));
    let before = session.document(checked.unwrap()).unwrap().text.clone();
    session.begin("Dropped", Origin::User);
    some_edits(&session);
    session.comment(0x1190, Some("changed")).unwrap();
    assert_ne!(session.edits(), edits);
    session.rollback();
    assert_eq!(session.edits(), edits);
    assert_eq!(file(&session), bytes);
    assert_eq!(session.history(), history);
    assert_eq!(session.saves(), saves);
    // Its function printed without them again.
    let after = session.document(checked.unwrap()).unwrap().text.clone();
    assert_eq!(after, before);
    session.close();
}

#[test]
fn a_changes_edits_say_each_value_and_the_one_before() {
    let dir = scratch("edits-of");
    let session = open(&dir);
    let classify = entry(&session, "classify");
    session.rename_function(classify, Some("sort")).unwrap();
    session.rename_function(classify, Some("order")).unwrap();
    let history = session.history();
    let (newest, older) = (history[0].id, history[1].id);
    let name = |text: &str| Value::Text(Some(text.to_owned()));
    // The first: no name of the user's before (the engine's own).
    assert_eq!(
        session.edits_of(older),
        [(Key::FunctionName(classify), name("sort"), Value::Text(None))]
    );
    // The second: the first's name before it.
    assert_eq!(
        session.edits_of(newest),
        [(Key::FunctionName(classify), name("order"), name("sort"))]
    );
    session.close();
}

#[test]
fn undo_and_redo_restore_the_project_file_byte_for_byte() {
    let dir = scratch("undo");
    let session = open(&dir);
    session.bookmark(0x1190, Some("first")).unwrap();
    let before = file(&session);
    session.begin("Several", Origin::User);
    some_edits(&session);
    session.bookmark(0x1190, Some("second")).unwrap();
    session.commit().unwrap();
    let after = file(&session);
    assert_ne!(after, before);
    let undone = session.undo().unwrap().unwrap();
    assert_eq!(undone.label, "Several");
    assert_eq!(undone.skipped, Vec::new());
    assert_eq!(file(&session), before);
    assert!(session.can_redo());
    session.redo().unwrap().unwrap();
    assert_eq!(file(&session), after);
    // Undone twice: before the first bookmark too; redo is gone after an
    // edit.
    session.undo().unwrap();
    session.undo().unwrap();
    assert_eq!(session.edits().bookmark(0x1190), None);
    assert!(!session.can_undo());
    session.comment(0x1190, Some("new")).unwrap();
    assert!(!session.can_redo());
    assert!(session.redo().unwrap().is_none());
    // Undo outside a group only.
    session.begin("Open", Origin::User);
    assert!(session.undo().is_err());
    session.rollback();
    session.close();
}

#[test]
fn an_edit_made_while_the_debug_information_is_taken_survives_the_swap() {
    // The binary alone (its debug file not beside it), its project in a
    // directory of this test's.
    let dir = scratch("swap");
    let binary = dir.join("units-x86_64.elf");
    fs::copy(fixture("units-x86_64.elf"), &binary).unwrap();
    let lineage = Lineage::open(&binary, options(&dir.join("project"))).unwrap();
    let events = lineage.subscribe(None);
    let session = lineage.session();
    session.wait(Stage::Analysed, None);
    let (scale, entry) = {
        let database = session.database().unwrap();
        database
            .functions()
            .find(|(_, f)| database.name(f.entry) == Some("scale"))
            .map(|(id, f)| (id, f.entry))
            .unwrap()
    };
    // The debug information fetched: the binary is opened again with it,
    // and the function renamed while that one is analysed.
    lineage.with_debug(fixture("units-x86_64.debug")).unwrap();
    assert!(lineage.reanalysing());
    session.rename_function(entry, Some("carried")).unwrap();
    let swapped = lineage.wait(Some(Duration::from_secs(120))).unwrap();
    let now = lineage.session();
    assert!(now.debug_file().is_some());
    assert_eq!(now.revision().analysis, 1);
    assert_eq!(now.revision().edits, 1);
    assert_eq!(now.edits().name(entry), Some("carried"));
    let scale_now = now.database().unwrap().function_at(entry).unwrap();
    assert_eq!(swapped.functions.get(&scale), Some(&scale_now));
    // Told: the session in use's events, the swap, then the new one's
    // (its stage may be told just after the swap: waited for; it may be
    // one past `Analysed`, reached before the lineage listened to it).
    let mut told: Vec<Event> = Vec::new();
    let relayed = |told: &[Event]| {
        told.iter()
            .position(|event| matches!(event, Event::Reanalysed { .. }))
            .is_some_and(|at| {
                told[at..]
                    .iter()
                    .any(|e| matches!(e, Event::Stage(stage) if *stage >= Stage::Analysed))
            })
    };
    while !relayed(&told) {
        told.push(events.recv_timeout(Duration::from_secs(60)).unwrap());
    }
    // In the C of the session swapped in, and in the project it saves.
    let text = now
        .document_view(scale_now, View::Exact)
        .unwrap()
        .text
        .clone();
    assert!(text.contains("carried("), "{text}");
    let saved = binbun_session::Edits::load(&now.project().unwrap().edits()).unwrap();
    assert_eq!(saved.name(entry), Some("carried"));
    // And undone there as an edit of it.
    now.undo().unwrap();
    assert_eq!(now.edits().name(entry), None);
    lineage.close();
}

#[test]
fn a_correction_is_analysed_anew_swapped_in_and_undone_per_key() {
    let dir = scratch("corrections");
    let lineage = Lineage::open(fixture("program-x86_64.elf"), options(&dir)).unwrap();
    let session = lineage.session();
    session.wait(Stage::Analysed, None);
    let fail: FunctionId = session.database().unwrap().function_at(0x11b0).unwrap();
    // `P` in `classify`'s padding, then a comment: two undo steps.
    let mut made = Corrections::default();
    made.set_bounds(0x11a3, Some(Bounds::Function { end: None }));
    session.set_corrections(&made).unwrap();
    session.comment(0x1190, Some("kept")).unwrap();
    assert!(!lineage.reanalysing());
    assert!(lineage.reanalyse().unwrap());
    assert!(!lineage.reanalyse().unwrap(), "one under way");
    let swapped = lineage.wait(Some(Duration::from_secs(120))).unwrap();
    let now = lineage.session();
    assert_eq!(now.revision().analysis, 1);
    let database = now.database().unwrap();
    assert!(database.function_at(0x11a3).is_some());
    assert_eq!(
        swapped.functions.get(&fail),
        database.function_at(0x11b0).as_ref()
    );
    // The comment undone first; the correction then, alone.
    now.undo().unwrap();
    assert_eq!(now.edits().comment(0x1190), None);
    now.comment(0x1194, Some("later")).unwrap();
    let undone = now.undo().unwrap().unwrap();
    assert_eq!(undone.label, "Comment");
    let undone = now.undo().unwrap().unwrap();
    assert_eq!(undone.label, "Correct recovery");
    assert!(now.corrections().is_empty());
    assert_eq!(now.recovered_as_corrected(), Some(false));
    assert!(lineage.reanalyse().unwrap());
    lineage.wait(Some(Duration::from_secs(120))).unwrap();
    let again = lineage.session();
    assert!(again.database().unwrap().function_at(0x11a3).is_none());
    assert_eq!(again.revision().analysis, 2);
    lineage.close();
}
