#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! What every front end reads of a session, on the checked-in fixture:
//! waiting for a stage and for an answer, the revision, an ephemeral
//! session that writes nothing, each document's provenance, the listing
//! with the user's edits laid over it, and the searches through it, the C
//! and the bytes; where the C declares locals, changed live.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use binbun::Database;
use binbun::cfg::FunctionId;
use binbun::corrections::instruction_length;
use binbun_ast::ir::{Node, VarKind};
use binbun_print::document::TokenKind;
use binbun_session::listing::{LineKind, Options as ListingOptions};
use binbun_session::search::{
    ByteMode, BytePattern, Matcher, Query, Search, Source, TextHit, TextRows,
};
use binbun_session::{
    Answer, Options, Placement, Question, Revision, Session, Stage, Unanswered, View, Waited, Wake,
};
use common::Scratch;

/// The fixture: `classify` called by `checked`, called by `loop_sum`.
fn binary() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf")
}

/// A directory of its own for test `name`, empty.
fn scratch(name: &str) -> Scratch {
    Scratch::new(&format!("{name}.reading"))
}

/// An ephemeral session on the fixture, its functions recovered.
fn ephemeral() -> Session {
    ephemeral_on(binary())
}

/// An ephemeral session on fixture `path`, its functions recovered.
fn ephemeral_on(path: PathBuf) -> Session {
    let session = Session::open(
        path,
        Options {
            ephemeral: true,
            ..Options::default()
        },
    )
    .unwrap();
    let waited = session.wait(Stage::Callers, Some(Duration::from_secs(120)));
    assert!(matches!(waited, Waited::Reached(_)), "{waited:?}");
    session
}

/// Every item `search` finds, once it is done.
fn drain<T: Send + 'static>(mut search: Search<T>) -> Vec<T> {
    let mut out = Vec::new();
    while search.is_running() {
        out.extend(
            search
                .wait(Duration::from_millis(100))
                .map(|batch| batch.items),
        );
    }
    out.extend(search.poll().into_iter().map(|batch| batch.items));
    assert!(search.is_done(), "the search stopped early");
    out.into_iter().flatten().collect()
}

fn quiet() -> Wake {
    Arc::new(|| {})
}

#[test]
fn waiting_returns_at_the_stage_at_the_deadline_or_when_opening_fails() {
    let session = Session::open(
        binary(),
        Options {
            ephemeral: true,
            warm: false,
            ..Options::default()
        },
    )
    .unwrap();
    // No time at all: not there yet, or there already.
    match session.wait(Stage::Callers, Some(Duration::ZERO)) {
        Waited::TimedOut(stage) => assert!(stage < Stage::Callers),
        Waited::Reached(stage) => assert!(stage >= Stage::Callers),
        stopped @ Waited::Stopped { .. } => panic!("{stopped:?}"),
    }
    // Without warming, waiting for the warming is waiting for the callers.
    assert_eq!(
        session.wait(Stage::Warmed, None),
        Waited::Reached(Stage::Callers)
    );
    assert_eq!(session.stage(), Stage::Callers);
    session.close();

    let missing = Session::open(
        scratch("missing").join("no-such-binary"),
        Options {
            ephemeral: true,
            ..Options::default()
        },
    )
    .unwrap();
    let Waited::Stopped { stage, failure } = missing.wait(Stage::Image, None) else {
        panic!("a missing file was opened");
    };
    assert_eq!(stage, Stage::Opening);
    assert!(failure.unwrap().contains("no-such-binary"));
}

#[test]
fn an_ephemeral_session_keeps_its_edits_in_memory_and_writes_nothing() {
    let projects = scratch("ephemeral");
    let session = Session::open(
        binary(),
        Options {
            ephemeral: true,
            projects: Some(projects.to_path_buf()),
            ..Options::default()
        },
    )
    .unwrap();
    assert!(matches!(
        session.wait(Stage::Analysed, None),
        Waited::Reached(_)
    ));
    assert!(session.project().is_none());
    assert_eq!(session.key().unwrap().hex().len(), 64);
    let before = session.revision();
    let entry = session
        .database()
        .unwrap()
        .functions()
        .next()
        .unwrap()
        .1
        .entry;
    session.rename_function(entry, Some("first")).unwrap();
    session.comment(entry, Some("here")).unwrap();
    assert_eq!(session.edits().name(entry), Some("first"));
    assert_eq!(
        session.revision(),
        Revision {
            edits: before.edits + 2,
            ..before
        }
    );
    assert!(session.save().is_err());
    session.close();
    assert_eq!(
        fs::read_dir(&projects).unwrap().count(),
        0,
        "nothing written"
    );
}

#[test]
fn answers_are_waited_for_kept_and_cancelled() {
    let session = ephemeral();
    let id = session
        .database()
        .unwrap()
        .find_function("loop_sum")
        .unwrap();
    let asked = session.ask(id, View::Exact, Question::Verify(None));
    let Ok(Answer::Verified(verified)) = asked.wait(None) else {
        panic!("not verified");
    };
    // Asked again: the kept answer, at once.
    let again = session.ask(id, View::Exact, Question::Verify(None));
    let Ok(Answer::Verified(kept)) = again.wait(Some(Duration::ZERO)) else {
        panic!("not kept");
    };
    assert!(Arc::ptr_eq(&kept, &verified));
    // Cancelled before it is answered: no answer, and the lane goes on.
    let checked = session
        .database()
        .unwrap()
        .find_function("checked")
        .unwrap();
    let cancelled = session.ask(checked, View::Exact, Question::Verify(None));
    cancelled.cancel();
    assert_eq!(cancelled.wait(None).unwrap_err(), Unanswered::Cancelled);
    let next = session.ask(checked, View::Reading, Question::Explain);
    assert!(matches!(next.wait(None), Ok(Answer::Explained(Ok(_)))));
    // A closed session answers nothing more: a question answered in time keeps its answer, one
    // under way when it closes is cancelled (`close` cancels), and one not yet started is dropped.
    let session = Arc::new(session);
    let classify = session
        .database()
        .unwrap()
        .find_function("classify")
        .unwrap();
    let asked = session.ask(classify, View::Reading, Question::Stages);
    Arc::into_inner(session).unwrap().close();
    assert!(matches!(
        asked.wait(Some(Duration::from_secs(60))),
        Ok(Answer::Staged(_)) | Err(Unanswered::Cancelled | Unanswered::Dropped)
    ));
}

#[test]
fn every_line_of_every_document_is_made_from_its_functions_instructions() {
    let session = ephemeral();
    let database = session.database().unwrap();
    let mut lines = 0;
    for (id, function) in database.functions() {
        let Ok(document) = session.document(id) else {
            continue;
        };
        let code = instructions(database, id);
        assert_eq!(document.lines().len(), document.text.split('\n').count());
        for (n, line) in document.lines().iter().enumerate() {
            assert_eq!(document.line_text(n), &document.text[line.range.clone()]);
            for &address in &line.addresses {
                // An instruction of the function, where it starts.
                assert!(
                    code.contains(&address),
                    "{address:#x} of line {n} of {:#x}",
                    function.entry
                );
                assert!(document.lines_of(address).any(|m| m == n));
                lines += 1;
            }
            // Each token's instructions are its node's or its line's.
            for s in line.spans.clone() {
                let made: BTreeSet<u64> = document.span_addresses(s).iter().copied().collect();
                assert!(
                    made.iter().all(|a| document.lines_of(*a).next().is_some()),
                    "token {s} of {:#x}",
                    function.entry
                );
            }
        }
    }
    assert!(lines > 50, "{lines} line instructions");
    session.close();
}

/// The instructions of function `id` of `database` (its blocks'), by
/// address.
fn instructions(database: &Database<'_>, id: FunctionId) -> BTreeSet<u64> {
    let program = database.program();
    let mut out = BTreeSet::new();
    for &block in &database.function(id).unwrap().blocks {
        let block = &program.blocks[block];
        let mut at = block.start;
        while at < block.end {
            out.insert(at);
            at += instruction_length(database.image(), at).unwrap();
        }
    }
    out
}

/// Each line of function `name`'s document that came from instructions:
/// its text, trimmed, and their addresses.
fn line_sets(session: &Session, name: &str) -> Vec<(String, Vec<u64>)> {
    let id = session.database().unwrap().find_function(name).unwrap();
    let document = session.document(id).unwrap();
    document
        .lines()
        .iter()
        .enumerate()
        .filter(|(_, line)| !line.addresses.is_empty())
        .map(|(n, line)| {
            (
                document.line_text(n).trim().to_owned(),
                line.addresses.clone(),
            )
        })
        .collect()
}

#[test]
fn a_line_comes_from_every_instruction_folded_into_it() {
    let session = ephemeral();
    let lines = |name, expected: &[(&str, &[u64])]| {
        let expected: Vec<(String, Vec<u64>)> = expected
            .iter()
            .map(|&(text, addresses)| (text.to_owned(), addresses.to_vec()))
            .collect();
        assert_eq!(line_sets(&session, name), expected, "{name}");
    };
    // The division by 7 is the multiply-high sequence (but `i++`'s add at
    // 0x1219, scheduled inside it); the loop's test, the copy of `a1`
    // into `ebp` and the compare-and-branch; each `return` its copy into
    // `eax` (and the zeroing it copies) and its `ret`. The prologue (the
    // stack lowered, `rbx`, `rbp` and `r12` saved, the last two after
    // the early return's test) is the signature's; the epilogue, before
    // each `ret`, its return's (restores and the stack raised). The
    // nops (0x120d, 0x125d) are no line's.
    let division: Vec<u64> = [
        0x1210, 0x1213, 0x1216, 0x121d, 0x1224, 0x1228, 0x122a, 0x122c, 0x122e, 0x1231, 0x1238,
        0x123a, 0x123c, 0x1241,
    ]
    .to_vec();
    lines(
        "loop_sum",
        &[
            (
                "int32_t loop_sum(int32_t a1)",
                &[0x11f0, 0x11f4, 0x11fc, 0x1205],
            ),
            ("if (a1 <= 0)", &[0x11f8, 0x11fa]),
            ("return 0;", &[0x1260, 0x1262, 0x1264, 0x1268, 0x126c]),
            ("int32_t result = 0;", &[0x1201]),
            (
                "for (int32_t i = 0; i < a1; i++)",
                &[0x1203, 0x120a, 0x1219, 0x1243, 0x1246],
            ),
            ("result += checked(i % 7);", division.as_slice()),
            (
                "return result;",
                &[0x1248, 0x124a, 0x124f, 0x1254, 0x1258, 0x125c],
            ),
        ],
    );
    // One epilogue (`add rsp, 8` after the call): the closing brace's.
    lines(
        "checked",
        &[
            ("int32_t checked(int64_t a1)", &[0x11d0]),
            ("if ((a1 >> 31) & 1UL) {", &[0x11d4, 0x11d6]),
            ("fail(\"negative\");", &[0x11e4, 0x11eb]),
            ("binbun_unreachable();", &[0x11eb]),
            ("}", &[0x11d6]),
            ("return classify(a1) * 2;", &[0x11d8, 0x11e1, 0x11e3]),
            ("}", &[0x11dd]),
        ],
    );
    lines(
        "classify",
        &[(
            "return (uint32_t)a1 >= 7 ? -1 : (a1 + 10 + a1 * 10);",
            &[0x1190, 0x1193, 0x1196, 0x119b, 0x119f, 0x11a2],
        )],
    );
    // `xor eax, eax` before `printf` (the vector registers a variadic
    // call is told of) is no line's.
    lines(
        "main",
        &[
            ("int32_t main_2(int32_t a1)", &[0x1060]),
            (
                "printf(\"%d\\n\", loop_sum(a1 + 5));",
                &[0x1064, 0x1067, 0x106c, 0x1073, 0x1077],
            ),
            ("return 0;", &[0x107c, 0x1082]),
            ("}", &[0x107e]),
        ],
    );
    session.close();
}

#[test]
fn the_listing_is_kept_and_shows_the_users_names_and_comments() {
    let session = ephemeral();
    let options = ListingOptions::default();
    let listing = session.listing(&options).unwrap();
    assert!(Arc::ptr_eq(&listing, &session.listing(&options).unwrap()));
    let db = session.database().unwrap();
    let entry = db.functions().next().unwrap().1.entry;
    let shown = |listing: &binbun_session::listing::Listing, n| {
        listing.render(db, n, &session.overlay()).text()
    };
    let line = listing.line_of(entry);

    session
        .rename_function(entry, Some("renamed_here"))
        .unwrap();
    session.comment(entry, Some("one\ntwo")).unwrap();
    let overlay = session.overlay();
    assert_eq!(
        overlay.names.get(&entry).map(String::as_str),
        Some("renamed_here")
    );
    assert!(
        Arc::ptr_eq(&overlay, &session.overlay()),
        "kept until an edit"
    );
    let commented = session.listing(&options).unwrap();
    // A line more for the comment's second line, under its first.
    assert_eq!(commented.len(), listing.len() + 1);
    assert_eq!(commented.line(line + 1).unwrap().kind, LineKind::Comment);
    assert!(shown(&commented, line).ends_with("; one"));
    assert!(shown(&commented, line + 1).ends_with("; two"));
    let named = (0..commented.len()).any(|n| shown(&commented, n).contains("renamed_here"));
    assert!(named);
    session.close();
}

#[test]
fn a_name_the_user_gives_over_a_made_one_is_not_automatic() {
    let session = ephemeral();
    let listing = session.listing(&ListingOptions::default()).unwrap();
    let db = session.database().unwrap();
    // `lea rdi, aNegative` in `checked`: the string's name, made from its
    // text.
    let n = listing.line_of(0x11E4);
    let string = |listing: &binbun_session::listing::Listing| {
        listing
            .render(db, n, &session.overlay())
            .tokens
            .into_iter()
            .find(|t| t.role == binbun_session::listing::Role::DataName)
            .unwrap()
    };
    let made = string(&listing);
    assert_eq!((made.text.as_str(), made.automatic), ("aNegative", true));
    session
        .rename_global(made.target.unwrap(), Some("negative_text"))
        .unwrap();
    let given = string(&listing);
    assert_eq!(
        (given.text.as_str(), given.automatic),
        ("negative_text", false)
    );
    session.close();
}

#[test]
fn searches_find_the_listing_the_c_and_bytes_as_shown() {
    let session = Arc::new(ephemeral());
    let listing = session.listing(&ListingOptions::default()).unwrap();
    let db = session.database().unwrap();
    let checked = db.find_function("checked").unwrap();
    let checked_entry = db.function(checked).unwrap().entry;
    let classify = db
        .function(db.find_function("classify").unwrap())
        .unwrap()
        .entry;
    let matcher = Arc::new(
        Matcher::new(&Query {
            text: "classify".to_owned(),
            case: true,
            regex: false,
        })
        .unwrap()
        .unwrap(),
    );
    let hits = drain(session.search_text(Some(&listing), Some(View::Exact), &matcher, &quiet()));
    // The call in the listing and in the C, both in `checked`.
    assert!(hits.iter().any(|h| h.source == Source::Listing
        && h.function == Some(checked_entry)
        && h.text.starts_with("call")));
    // The call, at its line's first instruction (the declaration, made
    // from none, is at the entry), which the document links to the line.
    let in_c = hits
        .iter()
        .find(|h| {
            h.source == Source::C && h.function == Some(checked_entry) && h.address != checked_entry
        })
        .unwrap();
    assert!(in_c.text.contains("classify("));
    let document = session.document(checked).unwrap();
    assert!(
        document
            .lines_of(in_c.address)
            .any(|n| document.line_text(n).contains("classify("))
    );

    // The bytes at `classify`'s entry, the second a wildcard.
    let bytes = &db.image().segments.iter().find_map(|s| {
        let at = usize::try_from(classify.checked_sub(s.start)?).ok()?;
        s.bytes.get(at..at + 3)
    });
    let code = bytes.unwrap();
    let text = format!("{:02x} ?? {:02x}", code[0], code[2]);
    let pattern = Arc::new(BytePattern::parse(&text, ByteMode::Hex, false).unwrap());
    let found = drain(session.search_bytes(&pattern, false, &quiet()).unwrap());
    assert!(found.iter().any(|h| h.at == classify && h.bytes == code));
    for hit in &found {
        assert!(pattern.matches_at(&hit.bytes, 0));
    }
    drop(session);
}

/// Fixture `name` of `tests/fixtures`.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn a_declaration_every_function_prints_is_listed_once_and_is_no_code() {
    // `record`, which four functions use, each declaring it (and its
    // struct) in its C.
    let session = Arc::new(ephemeral_on(fixture("globals-x86_64.elf")));
    let record = session
        .database()
        .unwrap()
        .image()
        .symbols
        .iter()
        .find(|s| s.name == "record")
        .unwrap()
        .address;
    let matcher = Arc::new(
        Matcher::new(&Query {
            text: "record".to_owned(),
            case: true,
            regex: false,
        })
        .unwrap()
        .unwrap(),
    );
    let hits = drain(session.search_text(None, Some(View::Exact), &matcher, &quiet()));
    let declared = |hit: &TextHit| hit.text.starts_with("extern struct struct_fill_1 record;");
    // Every function's copy is a declaration of no function, at `record`.
    let copies: Vec<&TextHit> = hits.iter().filter(|h| declared(h)).collect();
    assert_eq!(copies.len(), 4, "{hits:#?}");
    for copy in &copies {
        assert_eq!(
            (copy.source, copy.address, copy.function),
            (Source::Declaration, record, None)
        );
    }
    // Its uses stay in their functions.
    assert!(
        hits.iter()
            .filter(|h| h.text.starts_with("record.field_"))
            .all(|h| h.source == Source::C && h.function.is_some())
    );
    // Listed once, whichever batches the copies come in.
    let mut rows = TextRows::default();
    for hit in hits.iter().rev() {
        rows.add(vec![hit.clone()]);
    }
    let listed: Vec<&TextHit> = rows.rows().iter().filter(|h| declared(h)).collect();
    assert_eq!(listed, vec![copies[0]]);
    // Each declaration once, the rest all there, in order.
    let mut texts: Vec<&str> = rows
        .rows()
        .iter()
        .filter(|h| h.source == Source::Declaration)
        .map(|h| h.text.as_str())
        .collect();
    let before = texts.len();
    texts.sort_unstable();
    texts.dedup();
    assert_eq!(texts.len(), before);
    let code = |hits: &mut dyn Iterator<Item = &TextHit>| {
        hits.filter(|h| h.source != Source::Declaration).count()
    };
    assert_eq!(code(&mut rows.rows().iter()), code(&mut hits.iter()));
    assert!(rows.rows().is_sorted_by(|a, b| a.key() <= b.key()));

    // A value is looked for in code: not in an array's length in a
    // declaration (`make` declares `_ZTV6Square[48]`).
    let session = Arc::new(ephemeral_on(fixture("classes-gcc-x86_64.elf")));
    let make = session.database().unwrap().find_function("make").unwrap();
    let document = session.document(make).unwrap();
    assert!(
        (0..document.definition).any(|n| document.line_text(n).contains("_ZTV6Square[48];")),
        "{}",
        document.text
    );
    let found = drain(session.search_immediate(None, Some(View::Exact), 48, &quiet()));
    assert!(
        found
            .iter()
            .all(|h| h.source == Source::C && !h.text.starts_with("extern")),
        "{found:#?}"
    );
}

#[test]
fn a_global_renamed_from_a_c_is_renamed_in_the_listing_and_every_c() {
    // `record`, which `fill` and `second` both print.
    let session = ephemeral_on(fixture("globals-x86_64.elf"));
    let db = session.database().unwrap();
    let [fill, second] = ["fill", "second"].map(|name| db.find_function(name).unwrap());
    let listing = session.listing(&ListingOptions::default()).unwrap();
    let words = |text: &str, name: &str| {
        text.split(|c: char| c != '_' && !c.is_ascii_alphanumeric())
            .filter(|word| *word == name)
            .count()
    };
    // Each line of the listing naming `name`, and how often each C does.
    let naming = |name: &str| {
        let overlay = session.overlay();
        let lines: Vec<u64> = (0..listing.len())
            .filter(|&n| words(&listing.render(db, n, &overlay).text(), name) > 0)
            .collect();
        let c = [fill, second].map(|f| words(&session.document(f).unwrap().text, name));
        (lines, c)
    };
    let (lines, c) = naming("record");
    assert!(
        !lines.is_empty() && c.iter().all(|&n| n > 0),
        "{lines:?} {c:?}"
    );
    let document = session.document(fill).unwrap();
    let global = document
        .spans
        .iter()
        .find_map(|span| match span.node {
            Some(Node::Var(var)) if span.kind == TokenKind::Global => Some(var),
            _ => None,
        })
        .unwrap();
    assert!(matches!(
        document.decompiled.l2.var(global).unwrap().kind,
        VarKind::Global(_)
    ));

    // Named from `fill`'s C as a variable is: the global is.
    let change = session
        .rename_variable(fill, global, Some("table"))
        .unwrap();
    assert!(change.documents.contains(&fill) && change.documents.contains(&second));
    assert_eq!(naming("table"), (lines.clone(), c));
    assert_eq!(naming("record"), (Vec::new(), [0, 0]));
    // Emptied, the field would show its own name.
    let renamed = session.document(fill).unwrap();
    assert_eq!(renamed.default_name(global), Some("record"));

    // One change: undone, the listing and both Cs name it as before.
    session.undo().unwrap().unwrap();
    assert_eq!(naming("record"), (lines, c));
    assert_eq!(naming("table"), (Vec::new(), [0, 0]));
    assert_eq!(session.document(fill).unwrap().text, document.text);
}

#[test]
fn declarations_change_live_and_the_documents_print_again() {
    let session = ephemeral();
    let id = session
        .database()
        .unwrap()
        .find_function("loop_sum")
        .unwrap();
    let scoped = session.document(id).unwrap();
    assert!(
        scoped.text.contains("for (int32_t i = 0; "),
        "{}",
        scoped.text
    );
    let style = session.style();
    let change = session.set_style(style.with_declarations(Placement::Top));
    assert!(change.documents.contains(&id), "{change:?}");
    assert_eq!(session.style().declarations, Placement::Top);
    let top = session.document(id).unwrap();
    assert!(top.text.contains("    int32_t i;\n"), "{}", top.text);
    assert!(top.text.contains("for (i = 0; "), "{}", top.text);
    // Already so: nothing to print again.
    assert_eq!(
        session
            .set_style(style.with_declarations(Placement::Top))
            .documents,
        []
    );
    session.set_style(style);
    assert_eq!(session.document(id).unwrap().text, scoped.text);
}
