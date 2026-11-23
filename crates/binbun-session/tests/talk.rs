#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Conversation through a session: a thread on a C line follows its
//! address across a
//! re-analysis that renumbers functions; a suggestion accepted in part
//! is one change by the person accepting, naming who suggested it, and
//! pending again once undone; evidence asked again is marked stale when
//! the analysis says otherwise; a draft writes nothing.

mod common;

use std::path::Path;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use binbun_session::journal::{Key, Origin, Value};
use binbun_session::talk::{
    Anchor, Author, Evidence, EvidenceItem, EvidenceRef, Mention, SuggestionState,
};
use binbun_session::{
    Bounds, Corrections, Event, Lineage, Located, Options, Say, Session, Stage, Suggesting, Typed,
    View,
};
use common::Scratch;

/// `tests/fixtures/program-x86_64.elf` (`classify` called by `checked`,
/// called by `loop_sum`).
fn fixture() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/program-x86_64.elf"
    ))
}

/// Options keeping the project in `dir`, no warming, an identity of the
/// tests' own.
fn options(dir: &Path) -> Options {
    Options {
        project: Some(dir.join("project")),
        identity: Some(dir.join("identity")),
        warm: false,
        ..Options::default()
    }
}

/// The entry of the function named `name`.
fn entry(session: &Session, name: &str) -> u64 {
    let database = session.database().unwrap();
    database
        .functions()
        .find(|(_, f)| session.name(f.entry).as_deref() == Some(name))
        .map(|(_, f)| f.entry)
        .unwrap()
}

/// The mentions told on `events` so far.
fn mentions(events: &Receiver<Event>) -> Vec<Mention> {
    events
        .try_iter()
        .filter_map(|event| {
            if let Event::Mentioned(mentioned) = event {
                Some(mentioned.mention.clone())
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn a_thread_on_a_c_line_follows_its_address_across_a_reanalysis_that_renumbers_functions() {
    let dir = Scratch::new("talk-renumbered");
    let lineage = Lineage::open(fixture(), options(&dir)).unwrap();
    let session = lineage.session();
    session.wait(Stage::Callers, None);
    // `checked` (after `classify`, whose padding gets a function).
    let checked = entry(&session, "checked");
    let before = session.database().unwrap().function_at(checked).unwrap();
    let document = session.document_view(before, View::Exact).unwrap();
    // Its last line made from an instruction: the anchor is that
    // instruction, the line where it first prints.
    let (address, line) = (0..document.lines().len())
        .rev()
        .find_map(|n| {
            let &address = document.provenance.addresses_of(n).first()?;
            (document.lines_of(address).next() == Some(n)).then_some((address, n))
        })
        .unwrap();
    let quote = document.line_text(line).trim().to_owned();
    let anchor = Anchor::Line {
        function: checked,
        reading: false,
        address,
    };
    let thread = session.open_thread(anchor.clone(), &quote).unwrap();
    session
        .post(
            thread,
            Say {
                body: "Why is this checked twice?".to_owned(),
                ..Say::default()
            },
        )
        .unwrap();
    // A function made in `classify`'s padding: every function after it
    // is numbered anew.
    let mut made = Corrections::default();
    made.set_bounds(0x11a3, Some(Bounds::Function { end: None }));
    session.set_corrections(&made).unwrap();
    assert!(lineage.reanalyse().unwrap());
    lineage.wait(Some(Duration::from_secs(120))).unwrap();
    let now = lineage.session();
    let database = now.database().unwrap();
    assert!(database.function_at(0x11a3).is_some());
    let after = database.function_at(checked).unwrap();
    assert_ne!(after, before, "renumbered");
    // The thread is there, at its address, about the function, and found
    // on the line printing the instruction now.
    let found = now.threads_at(address);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, thread);
    assert_eq!(found[0].posts[0].body, "Why is this checked twice?");
    assert_eq!(now.threads_of(checked)[0].id, thread);
    let Located::Line {
        function,
        view,
        line: Some(line),
    } = now.locate(&anchor)
    else {
        panic!("not on a line: {:?}", now.locate(&anchor));
    };
    assert_eq!((function, view), (after, View::Exact));
    let document = now.document_view(after, View::Exact).unwrap();
    assert!(document.provenance.addresses_of(line).contains(&address));
    assert_eq!(document.line_text(line).trim(), quote);
    // A thread on a function that is gone is detached.
    assert_eq!(
        now.locate(&Anchor::Function(0x1234_5678)),
        Located::Detached
    );
    lineage.close();
}

#[test]
fn a_suggestion_accepted_in_part_is_one_change_naming_both_and_pending_again_once_undone() {
    let dir = Scratch::new("talk-accept");
    let session = Session::open(fixture(), options(&dir)).unwrap();
    session.wait(Stage::Callers, None);
    let events = session.subscribe(None);
    let classify = entry(&session, "classify");
    let me = session.identity();
    let helper = Mention {
        key: me,
        agent: Some("script:helper".to_owned()),
    };
    // The person asks the helper in a thread: told to the helper.
    let thread = session
        .open_thread(Anchor::Function(classify), "int classify(int)")
        .unwrap();
    session
        .post(
            thread,
            Say {
                body: "@helper what is this?".to_owned(),
                mentions: vec![helper.clone()],
                ..Say::default()
            },
        )
        .unwrap();
    assert_eq!(mentions(&events), [helper]);
    assert!(!session.can_undo(), "conversation is no undo step");
    // The helper answers with a suggestion of two edits, then a second
    // version of it.
    let suggesting = |name: &str| Suggesting {
        label: "Name classify".to_owned(),
        edits: vec![
            (
                Key::FunctionName(classify),
                Value::Text(Some(name.to_owned())),
            ),
            (Key::Comment(classify), Value::Text(Some("sign".to_owned()))),
        ],
        rationale: "Returns -1, 0 or 1.".to_owned(),
        thread: Some(thread),
        ..Suggesting::default()
    };
    session.begin("Suggest", Origin::Script("helper".to_owned()));
    let first = session.suggest(suggesting("classify_sign")).unwrap();
    session.commit().unwrap();
    session.begin("Supersede", Origin::Script("helper".to_owned()));
    let second = session.supersede(first, suggesting("sign_of")).unwrap();
    session.commit().unwrap();
    assert_eq!(
        session.suggestion(first).unwrap().state,
        SuggestionState::Superseded(second)
    );
    assert_eq!(session.thread(thread).unwrap().suggestions, [first, second]);
    assert_eq!(
        session
            .pending_suggestions()
            .iter()
            .map(|s| s.id)
            .collect::<Vec<_>>(),
        [second]
    );
    // Nothing applied yet; the person accepts the name only.
    assert_eq!(session.name(classify).as_deref(), Some("classify"));
    let entry = session.accept(second, &[0]).unwrap().unwrap();
    assert_eq!(session.name(classify).as_deref(), Some("sign_of"));
    assert_eq!(session.edits().comment(classify), None);
    assert_eq!(entry.origin, Origin::Accept(second));
    assert_eq!(entry.author, me);
    assert_eq!(
        entry.suggested_by,
        Some(Author {
            key: me,
            origin: Origin::Script("helper".to_owned()),
        })
    );
    assert_eq!(
        session.suggestion(second).unwrap().state,
        SuggestionState::Accepted(vec![0])
    );
    assert!(session.accept(second, &[1]).is_err(), "accepted already");
    // Undone: the name goes, the suggestion waits again.
    session.undo().unwrap().unwrap();
    assert_eq!(session.name(classify).as_deref(), Some("classify"));
    assert_eq!(
        session.suggestion(second).unwrap().state,
        SuggestionState::Pending
    );
    // A key renamed since it was proposed shows as moved.
    session.rename_function(classify, Some("mine")).unwrap();
    let proposal = &session.suggestion(second).unwrap().edits[0];
    assert!(proposal.moved);
    assert_eq!(proposal.now, Some(Value::Text(Some("mine".to_owned()))));
    assert!(!session.suggestion(second).unwrap().edits[1].moved);
    session.close();
}

#[test]
fn evidence_asked_again_is_marked_stale_where_the_analysis_now_says_otherwise() {
    let dir = Scratch::new("talk-evidence");
    let session = Session::open(fixture(), options(&dir)).unwrap();
    session.wait(Stage::Callers, None);
    // `loop_sum`'s local `result`.
    let checked = entry(&session, "loop_sum");
    let id = session.database().unwrap().function_at(checked).unwrap();
    let document = session.document_view(id, View::Exact).unwrap();
    let (&var, _) = document
        .defaults
        .iter()
        .find(|(_, name)| *name == "result")
        .unwrap();
    let variable = session.variable(id, View::Exact, var).unwrap();
    let mut evidence = Evidence {
        items: vec![
            EvidenceItem {
                reference: EvidenceRef::Why {
                    function: checked,
                    reading: false,
                    variable: variable.clone(),
                },
                quote: None,
            },
            EvidenceItem {
                reference: EvidenceRef::Lines {
                    function: checked,
                    reading: false,
                    lines: vec![0],
                },
                quote: None,
            },
            EvidenceItem {
                reference: EvidenceRef::Text("It compares twice.".to_owned()),
                quote: None,
            },
        ],
    };
    let timeout = Some(Duration::from_secs(120));
    session.quote_evidence(&mut evidence, timeout);
    assert!(evidence.items.iter().all(|item| item.quote.is_some()));
    assert!(session.recheck(&evidence, timeout).iter().all(|r| !r.stale));
    // The variable typed by the user: why it has its type says otherwise
    // now; the line asked about and the agent's words do not.
    let quoted = evidence.items[0].quote.clone().unwrap();
    let ty = if quoted.contains("uint") {
        "int"
    } else {
        "unsigned int"
    };
    session
        .set_type(Typed::Variable(variable), Some(ty))
        .unwrap();
    let rechecked = session.recheck(&evidence, timeout);
    let stale: Vec<bool> = rechecked.iter().map(|r| r.stale).collect();
    assert_eq!(stale, [true, false, false]);
    let now = rechecked[0].now.as_ref().unwrap();
    assert!(
        now.contains("User") && !quoted.contains("User"),
        "{quoted} -> {now}"
    );
    session.close();
}

#[test]
fn a_draft_states_what_writes_would_do_and_leaves_the_group_open_as_it_was() {
    let dir = Scratch::new("talk-draft");
    let session = Session::open(fixture(), options(&dir)).unwrap();
    session.wait(Stage::Analysed, None);
    let classify = entry(&session, "classify");
    session.begin("Open", Origin::User);
    session.comment(classify, Some("kept")).unwrap();
    let (done, ops) = session.draft(|session| {
        session.rename_function(classify, Some("drafted")).unwrap();
        session.comment(classify, Some("drafted too")).unwrap();
        7
    });
    assert_eq!(done, 7);
    assert_eq!(
        ops,
        [
            (
                Key::FunctionName(classify),
                Value::Text(Some("drafted".to_owned()))
            ),
            (
                Key::Comment(classify),
                Value::Text(Some("drafted too".to_owned()))
            ),
        ]
    );
    assert_eq!(session.name(classify).as_deref(), Some("classify"));
    assert_eq!(session.edits().comment(classify), Some("kept"));
    let entry = session.commit().unwrap().unwrap();
    assert_eq!(entry.edits, 1);
    assert_eq!(session.edits().comment(classify), Some("kept"));
    session.close();
}
