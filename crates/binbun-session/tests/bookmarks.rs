#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Bookmarks beside this identity's own: every other author's as the
//! journal shows them, told as `Event::Bookmarks` when changes from
//! elsewhere (or a freeze) touch them; this install's private ones, kept
//! in the project's `private.toml` and nowhere else, each edit an undo
//! step in order with the journal's; a bookmark moved between shared and
//! private in one undo step either way; both, and the private halves of
//! the undo and redo steps, kept across reopening and a reanalysis' swap.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use binbun_session::journal::{FrozenBy, Key, Origin, SignedChange, Value};
use binbun_session::project::{self, Bundle};
use binbun_session::{Bounds, Corrections, Event, Lineage, Options, Session, Stage};
use common::Scratch;

/// `tests/fixtures/program-x86_64.elf`.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf")
}

/// Options keeping the project in `dir/project`, signing with the
/// identity in `dir/identity` (never the user's), no warming.
fn options(dir: &Path) -> Options {
    Options {
        project: Some(dir.join("project")),
        identity: Some(dir.join("identity")),
        warm: false,
        ..Options::default()
    }
}

/// A session on the fixture, its project and identity in `dir`, its
/// callers known.
fn open(dir: &Path) -> Session {
    let session = Session::open(fixture(), options(dir)).unwrap();
    session.wait(Stage::Callers, None);
    session
}

/// How many `Event::Bookmarks` were told on `events` so far.
fn told(events: &Receiver<Event>) -> usize {
    events
        .try_iter()
        .filter(|event| matches!(event, Event::Bookmarks))
        .count()
}

/// Whether `needle` is anywhere in `haystack`.
fn holds(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// The bytes of every file under `dir` but `private.toml`, by path.
fn shared_files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut todo = vec![dir.to_owned()];
    while let Some(dir) = todo.pop() {
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                todo.push(path);
            } else if path.file_name().is_some_and(|name| name != "private.toml") {
                found.insert(path.clone(), fs::read(&path).unwrap());
            }
        }
    }
    found
}

/// Every change `session` tells, chain by chain from each start.
fn everything(session: &Session) -> Vec<SignedChange> {
    session
        .tips_after(None, usize::MAX)
        .into_iter()
        .flat_map(|tip| session.changes_after(tip.chain, 0, usize::MAX, usize::MAX))
        .collect()
}

/// `(address, name)` as a private bookmarks map.
fn private(bookmarks: &[(u64, &str)]) -> BTreeMap<u64, String> {
    bookmarks
        .iter()
        .map(|&(address, name)| (address, name.to_owned()))
        .collect()
}

#[test]
fn private_bookmarks_undo_in_order_with_the_journals_edits_and_stay_local() {
    // Names no log or project file could hold by chance.
    const MINE: &str = "private-mine-7f3a";
    const RENAMED: &str = "private-renamed-7f3a";
    const SECOND: &str = "private-second-7f3a";
    let dir = Scratch::new("bookmarks-private");
    let session = open(&dir);
    let events = session.subscribe(None);
    assert!(!session.can_undo());
    session.bookmark_private(0x1190, Some(MINE)).unwrap();
    session.comment(0x1194, Some("shared note")).unwrap();
    session.bookmark_private(0x1190, Some(RENAMED)).unwrap();
    // Nothing changed: no step, nothing told.
    session.bookmark_private(0x11a3, None).unwrap();
    assert_eq!(session.private_bookmarks(), private(&[(0x1190, RENAMED)]));
    // Never a shared bookmark: not in the edits, the overlay or others'.
    assert!(session.edits().bookmarks().is_empty());
    assert!(session.overlay().bookmarks.is_empty());
    assert!(session.others_bookmarks().is_empty());
    assert_eq!(told(&events), 2);

    // Undone in the order made: the rename, the comment, the bookmark.
    let undone = session.undo().unwrap().unwrap();
    assert_eq!(undone.target, None);
    assert_eq!(undone.label, "Private bookmark");
    assert_eq!(session.private_bookmarks(), private(&[(0x1190, MINE)]));
    assert_eq!(session.edits().comment(0x1194), Some("shared note"));
    let undone = session.undo().unwrap().unwrap();
    assert!(undone.target.is_some());
    assert_eq!(session.edits().comment(0x1194), None);
    assert_eq!(session.private_bookmarks(), private(&[(0x1190, MINE)]));
    session.undo().unwrap().unwrap();
    assert!(session.private_bookmarks().is_empty());
    assert!(!session.can_undo());
    assert_eq!(session.undo().unwrap(), None);
    assert_eq!(told(&events), 2);
    // Made again in the same order.
    session.redo().unwrap().unwrap();
    assert_eq!(session.private_bookmarks(), private(&[(0x1190, MINE)]));
    assert_eq!(session.edits().comment(0x1194), None);
    session.redo().unwrap().unwrap();
    assert_eq!(session.edits().comment(0x1194), Some("shared note"));
    session.redo().unwrap().unwrap();
    assert_eq!(session.private_bookmarks(), private(&[(0x1190, RENAMED)]));
    assert!(!session.can_redo());
    assert_eq!(told(&events), 2);
    // A new private edit ends redo as an edit does.
    session.undo().unwrap();
    assert!(session.can_redo());
    session.bookmark_private(0x11a3, Some(SECOND)).unwrap();
    assert!(!session.can_redo());
    assert_eq!(
        session.private_bookmarks(),
        private(&[(0x1190, MINE), (0x11a3, SECOND)])
    );

    // Kept in `private.toml` alone: not in the project file or the log.
    let project = dir.join("project");
    let file = fs::read_to_string(project.join("private.toml")).unwrap();
    assert!(file.contains(MINE) && file.contains(SECOND), "{file}");
    let shared = shared_files(&project);
    assert!(
        shared
            .keys()
            .any(|path| path.starts_with(project.join("log")))
    );
    assert!(shared.values().any(|bytes| holds(bytes, "shared note")));
    for name in [MINE, RENAMED, SECOND] {
        assert!(!shared.values().any(|bytes| holds(bytes, name)), "{name}");
        for entry in session.history() {
            assert!(
                session
                    .edits_of(entry.id)
                    .iter()
                    .all(|(_, value, _)| *value != Value::Text(Some(name.to_owned())))
            );
        }
    }
    // Nor in an export of the project.
    let key = project::Key::of_file(&fixture()).unwrap();
    let exported = dir.join("program.binbun");
    project::export(&project::Project::new(&project), &key, &exported).unwrap();
    let bundle = Bundle::read(&exported).unwrap();
    assert!(
        bundle
            .files()
            .iter()
            .any(|(path, _)| path == "project.toml")
    );
    assert!(
        bundle
            .files()
            .iter()
            .all(|(path, _)| path != "private.toml")
    );
    let text = fs::read_to_string(&exported).unwrap();
    assert!(!text.contains(MINE) && !text.contains(SECOND));
    session.close();

    // Reopened: there still; an empty name removes one.
    let session = open(&dir);
    assert_eq!(
        session.private_bookmarks(),
        private(&[(0x1190, MINE), (0x11a3, SECOND)])
    );
    session.bookmark_private(0x1190, Some("")).unwrap();
    assert_eq!(session.private_bookmarks(), private(&[(0x11a3, SECOND)]));
    session.close();
}

#[test]
fn a_bookmark_moves_between_shared_and_private_in_one_undo_step_either_way() {
    let dir = Scratch::new("bookmarks-move");
    let session = open(&dir);
    let me = session.identity();
    let key = Key::Bookmark(me, 0x1190);
    session.bookmark(0x1190, Some("start")).unwrap();
    let events = session.subscribe(None);

    // Made private: its removal is the change; its name is kept privately.
    session.set_bookmark_private(0x1190, true).unwrap();
    assert_eq!(session.edits().bookmark(0x1190), None);
    assert_eq!(session.private_bookmarks(), private(&[(0x1190, "start")]));
    let made = session.history()[0].clone();
    assert_eq!(made.label, "Make bookmark private");
    assert_eq!(
        session.edits_of(made.id),
        vec![(
            key.clone(),
            Value::Text(None),
            Value::Text(Some("start".to_owned()))
        )]
    );
    assert_eq!(told(&events), 1);
    // Nothing to move: none shared there now, none private elsewhere.
    assert!(session.set_bookmark_private(0x1190, true).is_err());
    assert!(session.set_bookmark_private(0x2000, false).is_err());
    session.begin("group", Origin::User);
    assert!(session.set_bookmark_private(0x1190, false).is_err());
    session.rollback();

    // One undo step: shared again, not private; made again: private.
    let undone = session.undo().unwrap().unwrap();
    assert!(undone.target.is_some());
    assert_eq!(session.edits().bookmark(0x1190), Some("start"));
    assert!(session.private_bookmarks().is_empty());
    session.redo().unwrap().unwrap();
    assert_eq!(session.edits().bookmark(0x1190), None);
    assert_eq!(session.private_bookmarks(), private(&[(0x1190, "start")]));
    assert_eq!(told(&events), 2);

    // Shared back: its name is the change; it is private no more.
    session.set_bookmark_private(0x1190, false).unwrap();
    assert_eq!(session.edits().bookmark(0x1190), Some("start"));
    assert!(session.private_bookmarks().is_empty());
    let shared = session.history()[0].clone();
    assert_eq!(shared.label, "Share bookmark");
    assert_eq!(
        session.edits_of(shared.id),
        vec![(
            key,
            Value::Text(Some("start".to_owned())),
            Value::Text(None)
        )]
    );
    // Undone step by step: private again, shared again, never made.
    session.undo().unwrap();
    assert_eq!(session.edits().bookmark(0x1190), None);
    assert_eq!(session.private_bookmarks(), private(&[(0x1190, "start")]));
    session.undo().unwrap();
    assert_eq!(session.edits().bookmark(0x1190), Some("start"));
    assert!(session.private_bookmarks().is_empty());
    session.undo().unwrap();
    assert_eq!(session.edits().bookmark(0x1190), None);
    assert!(session.private_bookmarks().is_empty());
    assert!(!session.can_undo());
    // Told for the move and the two undoing a move, not the last.
    assert_eq!(told(&events), 3);
    session.close();
}

#[test]
fn others_bookmarks_are_each_authors_as_shown_and_told() {
    let dir = Scratch::new("bookmarks-others");
    let (ann, bob) = (open(&dir.join("ann")), open(&dir.join("bob")));
    ann.comment(0x1194, Some("first")).unwrap();
    bob.comment(0x11a3, Some("first")).unwrap();
    ann.bookmark(0x1190, Some("ann's")).unwrap();
    bob.bookmark(0x1190, Some("bob's")).unwrap();
    bob.bookmark(0x11a3, Some("gone soon")).unwrap();
    bob.bookmark(0x11a3, None).unwrap();
    bob.bookmark(0x11d0, Some("bob's other")).unwrap();
    let events = ann.subscribe(None);
    ann.receive(everything(&bob));
    bob.receive(everything(&ann));
    assert_eq!(told(&events), 1);

    // Each one's own in the overlay, the other's under its key.
    assert_eq!(
        ann.others_bookmarks(),
        BTreeMap::from([(
            bob.identity(),
            private(&[(0x1190, "bob's"), (0x11d0, "bob's other")])
        )])
    );
    assert_eq!(
        bob.others_bookmarks(),
        BTreeMap::from([(ann.identity(), private(&[(0x1190, "ann's")]))])
    );
    assert_eq!(ann.overlay().bookmarks, private(&[(0x1190, "ann's")]));
    assert_eq!(ann.edits().bookmarks(), &private(&[(0x1190, "ann's")]));

    // Bob's removal reaches Ann as one.
    bob.bookmark(0x11d0, None).unwrap();
    ann.receive(everything(&bob));
    assert_eq!(
        ann.others_bookmarks(),
        BTreeMap::from([(bob.identity(), private(&[(0x1190, "bob's")]))])
    );
    assert_eq!(told(&events), 1);
    // Ann's own edits are not others': not told.
    ann.bookmark(0x1194, Some("ann's second")).unwrap();
    assert_eq!(told(&events), 0);
    // Bob's chain frozen: his bookmarks gone, told; an author with none
    // left out.
    let cut = FrozenBy::Cut {
        record: 2,
        hash: [2; 32],
    };
    ann.freeze(&[(bob.chain(), 1, cut)]).unwrap();
    ann.settle();
    assert!(ann.others_bookmarks().is_empty());
    assert_eq!(told(&events), 1);
    ann.close();
    bob.close();
}

#[test]
fn private_bookmarks_and_their_undo_survive_a_reanalysis_swap() {
    let dir = Scratch::new("bookmarks-swap");
    let lineage = Lineage::open(fixture(), options(&dir)).unwrap();
    let session = lineage.session();
    session.wait(Stage::Analysed, None);
    let mut made = Corrections::default();
    made.set_bounds(0x11a3, Some(Bounds::Function { end: None }));
    session.set_corrections(&made).unwrap();
    session.bookmark_private(0x1190, Some("kept")).unwrap();
    assert!(lineage.reanalyse().unwrap());
    // Made while the new analysis runs: carried with the journal.
    session.bookmark_private(0x1194, Some("meanwhile")).unwrap();
    lineage.wait(Some(Duration::from_secs(120))).unwrap();
    let now = lineage.session();
    assert_eq!(now.revision().analysis, 1);
    assert_eq!(
        now.private_bookmarks(),
        private(&[(0x1190, "kept"), (0x1194, "meanwhile")])
    );
    assert_eq!(now.undo().unwrap().unwrap().target, None);
    assert_eq!(now.private_bookmarks(), private(&[(0x1190, "kept")]));
    assert_eq!(now.undo().unwrap().unwrap().target, None);
    assert_eq!(now.undo().unwrap().unwrap().label, "Correct recovery");
    lineage.close();
}

#[test]
fn an_ephemeral_sessions_private_bookmarks_are_kept_in_memory() {
    let dir = Scratch::new("bookmarks-ephemeral");
    let session = Session::open(
        fixture(),
        Options {
            ephemeral: true,
            warm: false,
            ..options(&dir)
        },
    )
    .unwrap();
    session.wait(Stage::Callers, None);
    session.bookmark_private(0x1190, Some("here")).unwrap();
    assert_eq!(session.private_bookmarks(), private(&[(0x1190, "here")]));
    session.undo().unwrap().unwrap();
    assert!(session.private_bookmarks().is_empty());
    session.close();
    assert!(!dir.join("project").exists());
}

#[test]
fn undo_and_redo_stay_whole_across_reopening() {
    let dir = Scratch::new("bookmarks-reopen-undo");
    let session = open(&dir);
    session.bookmark(0x1190, Some("start")).unwrap();
    session.set_bookmark_private(0x1190, true).unwrap();
    session.comment(0x1194, Some("note")).unwrap();
    session.bookmark_private(0x11a3, Some("solo")).unwrap();
    // The private edit alone undone: to make again after reopening.
    assert_eq!(session.undo().unwrap().unwrap().target, None);
    session.close();

    let session = open(&dir);
    assert_eq!(session.private_bookmarks(), private(&[(0x1190, "start")]));
    assert!(session.can_redo());
    assert_eq!(session.redo().unwrap().unwrap().target, None);
    assert_eq!(
        session.private_bookmarks(),
        private(&[(0x1190, "start"), (0x11a3, "solo")])
    );
    // Undone in order: the private edit alone, the comment, then the move
    // to private whole: shared again, and private no more.
    assert_eq!(session.undo().unwrap().unwrap().target, None);
    assert_eq!(session.private_bookmarks(), private(&[(0x1190, "start")]));
    assert!(session.undo().unwrap().unwrap().target.is_some());
    assert_eq!(session.edits().comment(0x1194), None);
    let undone = session.undo().unwrap().unwrap();
    assert_eq!(undone.label, "Make bookmark private");
    assert_eq!(session.edits().bookmark(0x1190), Some("start"));
    assert!(session.private_bookmarks().is_empty());
    session.close();

    // Made again after reopening, in order and whole.
    let session = open(&dir);
    session.redo().unwrap().unwrap();
    assert_eq!(session.edits().bookmark(0x1190), None);
    assert_eq!(session.private_bookmarks(), private(&[(0x1190, "start")]));
    session.redo().unwrap().unwrap();
    assert_eq!(session.edits().comment(0x1194), Some("note"));
    assert_eq!(session.redo().unwrap().unwrap().target, None);
    assert_eq!(
        session.private_bookmarks(),
        private(&[(0x1190, "start"), (0x11a3, "solo")])
    );
    assert!(!session.can_redo());
    // A change the private file never saw (a crash between the files,
    // its older copy put back): the move keeps its private half, the
    // private edit alone leaves undo, the bookmarks stay as they are.
    let file = dir.join("project").join("private.toml");
    let older = fs::read(&file).unwrap();
    session.comment(0x11b0, Some("later")).unwrap();
    session.close();
    fs::write(&file, older).unwrap();
    let session = open(&dir);
    assert_eq!(
        session.private_bookmarks(),
        private(&[(0x1190, "start"), (0x11a3, "solo")])
    );
    session.undo().unwrap().unwrap();
    assert_eq!(session.edits().comment(0x11b0), None);
    session.undo().unwrap().unwrap();
    assert_eq!(session.edits().comment(0x1194), None);
    session.undo().unwrap().unwrap();
    assert_eq!(session.edits().bookmark(0x1190), Some("start"));
    assert_eq!(session.private_bookmarks(), private(&[(0x11a3, "solo")]));
    session.close();
}
