#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! The log beside the project file: changes signed by this install's
//! identity and kept;
//! a project file without a log taken with the file unchanged; a change
//! tampered with refused; exported projects merged by their chains;
//! changes from a peer taken, conflicts shown and resolved.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use binbun_session::identity::Identity;
use binbun_session::journal::{FrozenBy, Key as JournalKey, Origin, SignedChange, Value};
use binbun_session::project::{self, Bundle, Key};
use binbun_session::{DebugSource, Edits, Event, Options, Session, Stage};

/// A cut by membership record 2.
const CUT: FrozenBy = FrozenBy::Cut {
    record: 2,
    hash: [2; 32],
};

/// Every change `session` tells, chain by chain from each start.
fn everything(session: &Session) -> Vec<SignedChange> {
    session
        .tips_after(None, usize::MAX)
        .into_iter()
        .flat_map(|tip| session.changes_after(tip.chain, 0, usize::MAX, usize::MAX))
        .collect()
}

/// `tests/fixtures/program-x86_64.elf`: `classify` called by `checked`,
/// called by `loop_sum`.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf")
}

/// A fresh directory for test `name` in this process (test binaries run at
/// once over one target directory share its temporary directory).
fn scratch(name: &str) -> PathBuf {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("log-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A session on `binary`, its project in `project`, its identity in
/// `identity`, its functions recovered.
fn open(binary: &Path, project: &Path, identity: &Path) -> Session {
    let session = Session::open(
        binary,
        Options {
            project: Some(project.to_owned()),
            identity: Some(identity.to_owned()),
            warm: false,
            debug: DebugSource::Without,
            ..Options::default()
        },
    )
    .unwrap();
    session.wait(Stage::Analysed, None);
    session
}

/// A project file stating every kind of edit.
const EVERY_KIND: &str = r#"format = 1

[[function]]
address = "0x1190"
name = "classify"

[[global]]
address = "0x4010"
name = "counter"

[[variable]]
function = "0x1190"
origins = ["register rdi", "value 3"]
name = "input"

[[variable]]
function = "0x1190"
origins = ["slot -24"]
ordinal = 1
name = "spill"

[[comment]]
address = "0x1194"
text = "two\nlines"

[[bookmark]]
address = "0x11b0"
name = "fail here"

[[slot]]
function = "0x11d0"
offset = -40
name = "saved"

[[number]]
address = "0x1198"
value = "0xffffffff"
form = "decimal"

[[number]]
address = "0x119c"
value = "0x41"
form = "char"

[[type]]
name = "struct pair"
c = "struct pair { int a; int b; };"

[[type]]
function = "0x1190"
c = "unsigned int classify(unsigned int value)"

[[type]]
global = "0x4010"
c = "unsigned long"

[[type]]
function = "0x1190"
origins = ["register rdi"]
c = "char *"

[[type]]
function = "0x11d0"
struct = 1
c = "struct frame { void *top; long argc; };"

[[item]]
address = "0x2000"
kind = "word"
count = 2

[[item]]
address = "0x2004"
kind = "undefined"
size = 9

[[bounds]]
function = "0x11a3"

[[bounds]]
function = "0x11d0"
end = "0x11e4"
"#;

#[test]
fn a_project_file_without_a_log_is_taken_with_the_file_unchanged() {
    let dir = scratch("unlogged");
    let project = dir.join("project");
    fs::create_dir_all(&project).unwrap();
    // Written as binbun writes it: what the projection gives back.
    let text = Edits::parse(EVERY_KIND).unwrap().to_toml().unwrap();
    fs::write(project.join("project.toml"), &text).unwrap();
    let identity = dir.join("identity");
    for _ in 0..2 {
        let session = open(&fixture(), &project, &identity);
        assert_eq!(
            fs::read_to_string(project.join("project.toml")).unwrap(),
            text
        );
        assert_eq!(session.edits(), Edits::parse(&text).unwrap());
        // One change, the import, by this install's identity; not undone.
        let history = session.history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].origin, Origin::Import("project.toml".to_owned()));
        assert_eq!(
            history[0].author,
            Identity::load_or_create(&identity).unwrap().public()
        );
        assert!(!session.can_undo());
        session.close();
    }
    assert!(project.join("log/project").exists());
}

#[test]
fn changes_are_kept_signed_and_undone_after_reopening() {
    let dir = scratch("kept");
    let (project, identity) = (dir.join("project"), dir.join("identity"));
    let session = open(&fixture(), &project, &identity);
    session.rename_function(0x1190, Some("sort")).unwrap();
    session.comment(0x1194, Some("here")).unwrap();
    let file = fs::read(project.join("project.toml")).unwrap();
    session.close();

    // A project file changed outside the log (by hand) is taken.
    let session = open(&fixture(), &project, &identity);
    assert_eq!(fs::read(project.join("project.toml")).unwrap(), file);
    let history = session.history();
    assert_eq!(history.len(), 2);
    assert!(history.iter().all(|entry| entry.mine));
    session.undo().unwrap().unwrap();
    assert_eq!(session.edits().comment(0x1194), None);
    assert_eq!(session.edits().function(0x1190), Some("sort"));
    session.close();
    let edited = fs::read_to_string(project.join("project.toml"))
        .unwrap()
        .replace("sort", "order");
    fs::write(project.join("project.toml"), &edited).unwrap();
    let session = open(&fixture(), &project, &identity);
    assert_eq!(session.edits().function(0x1190), Some("order"));
    assert_eq!(
        session.history()[0].origin,
        Origin::Import("project.toml".to_owned())
    );
    session.close();
}

#[test]
fn a_change_tampered_with_is_refused_and_listed() {
    let dir = scratch("tamper");
    let (project, identity) = (dir.join("project"), dir.join("identity"));
    let session = open(&fixture(), &project, &identity);
    session.rename_function(0x1190, Some("first")).unwrap();
    session.rename_function(0x11b0, Some("second")).unwrap();
    session.close();
    let chains = project.join("log/chains");
    let log = fs::read_dir(&chains)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut bytes = fs::read(&log).unwrap();
    let at = bytes.windows(6).rposition(|w| w == b"second").unwrap();
    bytes[at] = b'S';
    fs::write(&log, &bytes).unwrap();

    let session = open(&fixture(), &project, &identity);
    let refused = session.refused();
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert!(refused[0].why.contains("commits"), "{refused:?}");
    assert_eq!(session.edits().function(0x1190), Some("first"));
    assert_eq!(session.edits().function(0x11b0), None);
    // Its chain broken, this install writes on a chain of its own.
    session.comment(0x1194, Some("after")).unwrap();
    session.close();
    assert_eq!(fs::read_dir(&chains).unwrap().count(), 2);
}

#[test]
fn concurrent_renames_from_a_peer_are_a_conflict_until_resolved() {
    let dir = scratch("peers");
    let (ann_project, bob_project) = (dir.join("ann"), dir.join("bob"));
    let ann = open(&fixture(), &ann_project, &dir.join("ann-identity"));
    ann.comment(0x1194, Some("shared")).unwrap();
    ann.close();
    // Bob's copy of the project: the same project, his own identity.
    fs::create_dir_all(bob_project.join("log")).unwrap();
    for file in ["log/project", "log/bound"] {
        fs::copy(ann_project.join(file), bob_project.join(file)).unwrap();
    }
    let ann = open(&fixture(), &ann_project, &dir.join("ann-identity"));
    let bob = open(&fixture(), &bob_project, &dir.join("bob-identity"));
    let theirs = bob.receive(everything(&ann));
    assert_eq!(theirs.changes.len(), 1);
    assert_eq!(bob.edits().comment(0x1194), Some("shared"));

    ann.rename_function(0x1190, Some("aes_init")).unwrap();
    bob.rename_function(0x1190, Some("key_setup")).unwrap();
    let to_bob = bob.receive(everything(&ann));
    let to_ann = ann.receive(everything(&bob));
    assert_eq!((to_bob.conflicts.len(), to_ann.conflicts.len()), (1, 1));
    assert_eq!(ann.conflicts(), bob.conflicts());
    let conflict = &ann.conflicts()[0];
    assert_eq!(conflict.key, JournalKey::FunctionName(0x1190));
    assert_eq!(ann.edits().function(0x1190), bob.edits().function(0x1190));
    assert_eq!(
        ann.tips_after(None, usize::MAX),
        bob.tips_after(None, usize::MAX)
    );

    ann.resolve(
        conflict.key.clone(),
        Value::Text(Some("aes_init".to_owned())),
    )
    .unwrap();
    bob.receive(everything(&ann));
    assert!(ann.conflicts().is_empty() && bob.conflicts().is_empty());
    assert_eq!(bob.edits().function(0x1190), Some("aes_init"));
    // Bob's undo is his own change's: skipped, Ann's resolution since.
    let undone = bob.undo().unwrap().unwrap();
    assert_eq!(undone.skipped.len(), 1);
    assert_eq!(undone.skipped[0].by, vec![ann.history()[0].author]);
    ann.close();
    bob.close();
    // Taken changes are kept: Bob reopened still has Ann's.
    let bob = open(&fixture(), &bob_project, &dir.join("bob-identity"));
    assert_eq!(bob.edits().function(0x1190), Some("aes_init"));
    assert_eq!(bob.tips_after(None, usize::MAX).len(), 2);
    bob.close();
}

#[test]
fn a_frozen_chain_no_longer_counts_now_or_after_reopening() {
    let dir = scratch("freeze");
    let (ann_project, bob_project) = (dir.join("ann"), dir.join("bob"));
    let ann = open(&fixture(), &ann_project, &dir.join("ann-identity"));
    ann.rename_function(0x1190, Some("ann_name")).unwrap();
    ann.close();
    fs::create_dir_all(bob_project.join("log")).unwrap();
    for file in ["log/project", "log/bound"] {
        fs::copy(ann_project.join(file), bob_project.join(file)).unwrap();
    }
    let ann = open(&fixture(), &ann_project, &dir.join("ann-identity"));
    let bob = open(&fixture(), &bob_project, &dir.join("bob-identity"));
    bob.receive(everything(&ann));
    // Bob writes three changes: one within a cut, two past it.
    bob.comment(0x1194, Some("kept")).unwrap();
    let (chain, cut) = (bob.chain(), bob.tip(bob.chain()).unwrap().seq);
    bob.rename_function(0x1190, Some("bob_name")).unwrap();
    bob.rename_function(0x11d0, Some("bob_other")).unwrap();
    ann.receive(everything(&bob));
    // Ann names 0x11d0 after Bob, seeing his.
    ann.rename_function(0x11d0, Some("ann_after")).unwrap();
    assert_eq!(ann.edits().function(0x1190), Some("bob_name"));
    let events = ann.subscribe(None);
    let frozen = ann.freeze(&[(chain, cut + 1, CUT)]).unwrap();
    assert_eq!(frozen.frozen, [(chain, cut + 1)]);
    // Marked at once, taken out in turns after (sync §4.3): his two past
    // the cut are dropped and listed; his name gives way to Ann's before
    // it, Ann's later one stands; his comment stays.
    ann.settle();
    let refused: Vec<_> = ann
        .refused()
        .into_iter()
        .filter(|refused| refused.change.is_some_and(|id| id.chain == chain))
        .collect();
    assert_eq!(refused.len(), 2);
    assert!(refused.iter().all(|refused| refused.why.contains("cut")));
    assert_eq!(ann.edits().function(0x1190), Some("ann_name"));
    assert_eq!(ann.edits().function(0x11d0), Some("ann_after"));
    assert_eq!(ann.edits().comment(0x1194), Some("kept"));
    assert_eq!(ann.conflicts(), []);
    assert_eq!(ann.tip(chain).unwrap().seq, cut);
    assert!(
        ann.history()
            .iter()
            .all(|entry| entry.id.chain != chain || entry.id.seq <= cut)
    );
    let told: Vec<Event> = events.try_iter().collect();
    assert!(told.iter().any(|event| matches!(event, Event::Changed(_))));
    assert!(
        told.iter()
            .any(|event| matches!(event, Event::History(entries) if entries.is_empty()))
    );
    // The chain is refused from there on; freezing it again does nothing.
    let again = ann.receive(everything(&bob));
    assert_eq!(again.changes.len(), 0);
    assert_eq!(ann.freeze(&[(chain, cut + 2, CUT)]).unwrap().refused, []);
    // Bob, frozen on his own side too, goes on on a new chain; his undo
    // is of the change within the cut.
    bob.freeze(&[(chain, cut + 1, CUT)]).unwrap();
    bob.settle();
    assert_eq!(bob.edits().function(0x1190), Some("ann_name"));
    bob.new_chain().unwrap();
    assert_eq!(bob.undo().unwrap().unwrap().target.unwrap().seq, cut);
    assert_ne!(bob.chain(), chain);
    let after = ann.receive(everything(&bob));
    assert_eq!(after.changes.len(), 1);
    assert_eq!(ann.edits().comment(0x1194), None);
    let file = fs::read(ann_project.join("project.toml")).unwrap();
    ann.close();
    bob.close();
    // Reopened: the freeze holds, the project file as it was.
    let ann = open(&fixture(), &ann_project, &dir.join("ann-identity"));
    assert_eq!(ann.edits().function(0x1190), Some("ann_name"));
    assert_eq!(ann.frozen()[&chain], cut + 1);
    assert_eq!(fs::read(ann_project.join("project.toml")).unwrap(), file);
    ann.close();
}

/// `/usr/bin/bash`'s first `count` functions' entries.
fn entries(session: &Session, count: usize) -> Vec<u64> {
    session
        .database()
        .unwrap()
        .functions()
        .map(|(_, f)| f.entry)
        .take(count)
        .collect()
}

#[test]
fn two_exports_of_bash_merge_by_their_chains() {
    let bash = Path::new("/usr/bin/bash");
    if !bash.exists() {
        return;
    }
    let dir = scratch("merge");
    let key = Key::of_file(bash).unwrap();
    let mut bundles = Vec::new();
    for (who, name) in [("ann", "ann"), ("bob", "bob")] {
        let root = dir.join(who);
        let session = open(
            bash,
            project::locate(&root, &key, &project::Choice::Any)
                .unwrap()
                .project
                .dir(),
            &dir.join(format!("{who}-identity")),
        );
        let shared = entries(&session, 8);
        session.begin("Name", Origin::User);
        // Five functions both name; three comments each, one at an
        // address both comment.
        for (n, &entry) in shared.iter().take(5).enumerate() {
            session
                .rename_function(entry, Some(&format!("{name}_{n}")))
                .unwrap();
        }
        let own = if who == "ann" {
            &shared[4..7]
        } else {
            &shared[2..5]
        };
        for &entry in own {
            session
                .comment(entry, Some(&format!("{name} was here")))
                .unwrap();
        }
        session.commit().unwrap();
        let project = session.project().unwrap().clone();
        session.close();
        let file = dir.join(format!("{who}.binbun"));
        project::export(&project, &key, &file).unwrap();
        bundles.push(Bundle::read(&file).unwrap());
    }
    let ann_root = dir.join("ann");
    let ann = Identity::load_or_create(&dir.join("ann-identity")).unwrap();
    let merged = project::merge(&bundles[1], &ann_root, &ann).unwrap();
    assert_eq!(merged.applied.changes.len(), 1);
    assert_eq!(merged.applied.refused, Vec::new());
    // Every key both set is a conflict: the five names, the one comment.
    let session = open(bash, merged.project.dir(), &dir.join("ann-identity"));
    let conflicts = session.conflicts();
    assert_eq!(conflicts.len(), 5 + 1, "{conflicts:?}");
    // Nothing lost: every name and comment either made is a value.
    let shared = entries(&session, 8);
    for (n, &entry) in shared.iter().take(5).enumerate() {
        let conflict = conflicts
            .iter()
            .find(|c| c.key == JournalKey::FunctionName(entry))
            .unwrap();
        let values: Vec<Value> = conflict.leaves.iter().map(|l| l.value.clone()).collect();
        for who in ["ann", "bob"] {
            assert!(values.contains(&Value::Text(Some(format!("{who}_{n}")))));
        }
    }
    let edits = session.edits();
    for &entry in &shared[2..7] {
        assert!(edits.comment(entry).is_some(), "{entry:#x}");
    }
    // The union of chains: Ann's and Bob's.
    assert_eq!(session.tips_after(None, usize::MAX).len(), 2);
    session.close();
}

#[test]
fn a_thousand_edits_commit_as_one_change_at_the_cost_of_a_save() {
    let bash = Path::new("/usr/bin/bash");
    if !bash.exists() {
        return;
    }
    let dir = scratch("cost");
    let session = open(bash, &dir.join("project"), &dir.join("identity"));
    let shared = entries(&session, 1000);
    let name_all = |prefix: &str| {
        session.begin("Name a thousand", Origin::User);
        for (n, &entry) in shared.iter().enumerate() {
            session
                .rename_function(entry, Some(&format!("{prefix}{n}")))
                .unwrap();
        }
    };
    // The log made by a first such change.
    name_all("f");
    session.commit().unwrap();
    name_all("g");
    // Today's per-edit cost: the project file written with these edits.
    let edits = session.edits();
    let file = session.project().unwrap().edits();
    let saved = Instant::now();
    for _ in 0..5 {
        edits.save(&file).unwrap();
    }
    let save = saved.elapsed() / 5;
    let committed = Instant::now();
    let made = session.commit().unwrap().unwrap();
    let commit = committed.elapsed();
    assert_eq!(made.edits, 1000);
    let log = fs::read_dir(dir.join("project/log/chains"))
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum::<u64>();
    eprintln!(
        "cost: save {save:?}, commit of 1,000 ops {commit:?}, log {log} bytes ({} per rename)",
        log / 2000
    );
    // The target (twice a save) is measured, not asserted: timings under
    // a loaded test run are noise. Each rename is one op of the change,
    // its log a few dozen bytes.
    assert!(log / 2000 < 64, "{log} bytes for 2,000 renames");
    session.close();
}
