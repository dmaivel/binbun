#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]
//! Undo and redo through the host: a private bookmark's edit alone (the
//! GUI's, local) is a step like a change, told as an item of no change
//! rather than as nothing left to undo.

use std::fs;
use std::path::Path;
use std::process;
use std::sync::Arc;

use binbun_protocol::Host;
use binbun_session::{Lineage, Options, Stage};

#[test]
fn a_private_bookmarks_edit_alone_is_told_as_a_step_of_no_change() {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("undo-private-{}", process::id()));
    let _ = fs::remove_dir_all(&dir);
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf");
    let options = Options {
        project: Some(dir.join("project")),
        identity: Some(dir.join("identity")),
        warm: false,
        ..Options::default()
    };
    let lineage = Arc::new(Lineage::open(fixture, options).unwrap());
    let session = lineage.session();
    session.wait(Stage::Callers, None);
    let host = Host::new(Arc::clone(&lineage), false);
    session.comment(0x1194, Some("shared")).unwrap();
    session.bookmark_private(0x1190, Some("mine")).unwrap();

    let undone = host.undo().unwrap().unwrap();
    assert_eq!(
        (undone.id.as_str(), undone.author.as_str(), undone.edits),
        ("", "undo", 0)
    );
    assert_eq!(undone.label, "Private bookmark");
    assert_eq!(undone.key, session.identity().to_string());
    assert!(session.private_bookmarks().is_empty());
    // The change under it comes next, as a change.
    let comment = host.undo().unwrap().unwrap();
    assert_eq!((comment.author.as_str(), comment.edits), ("undo", 1));
    assert_eq!(
        host.history().first().map(|newest| newest.id.as_str()),
        Some(comment.id.as_str())
    );
    assert_eq!(session.edits().comment(0x1194), None);
    assert_eq!(host.undo().unwrap(), None);

    host.redo().unwrap().unwrap();
    let redone = host.redo().unwrap().unwrap();
    assert_eq!((redone.id.as_str(), redone.author.as_str()), ("", "redo"));
    assert_eq!(
        session.private_bookmarks().get(&0x1190).map(String::as_str),
        Some("mine")
    );
    assert_eq!(host.redo().unwrap(), None);
    drop(host);
    Arc::try_unwrap(lineage).unwrap().close();
    let _ = fs::remove_dir_all(&dir);
}
