#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Sessions on a checked-in binary: C on request as `binbun decompile`
//! prints it, during and after the analysis; edits that print again only
//! what they name, survive saving and reopening, and are reported when
//! they no longer resolve; cancelling stops the worker; debug information
//! found beside the binary (or given, or ignored) printing as
//! `binbun decompile --debug` (or without) prints, with each function's
//! compilation unit; call sites with their callers' C lines in the user's
//! names, and paths.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::calls::sites::Known;
use binbun::calls::{Node as Callee, PathQuery};
use binbun::cfg::FunctionId;
use binbun::decompile::{Options as DecompileOptions, View};
use binbun::queries::lower;
use binbun::queries::origin::{Query, Start, origins};
use binbun::queries::verify::{self, Verdict};
use binbun::run::{self, ExampleState};
use binbun::stages::{self, stages};
use binbun_ast::ir::{Node, Origin, VarId, VarKind};
use binbun_loader::Image;
use binbun_print::document::TokenKind;
use binbun_print::style::IntSpelling;
use binbun_session::{
    Answer, DebugSource, Document, Edit, EnumLayout, Error, Event, Lineage, MemberEdit, NumberForm,
    Options, PathRequest, Question, Session, Stage, TypeLayout, Typed, Unresolved, Waited,
};
use binbun_ssa::ir::Definition;
use common::Scratch;

/// The fixture: `classify` called by `checked`, called by `loop_sum`.
fn binary() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf")
}

/// A project directory of its own for test `name`, empty.
fn project(name: &str) -> Scratch {
    Scratch::new(&format!("{name}.project"))
}

/// The identity these tests sign their changes with: never the user's.
fn identity() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("identity")
}

/// A session on the fixture with the project in directory `project`.
fn open(project: &Path) -> Session {
    Session::open(
        binary(),
        Options {
            project: Some(project.to_owned()),
            identity: Some(identity()),
            ..Options::default()
        },
    )
    .unwrap()
}

/// Waits on `events` for `stage`.
fn wait_for(events: &Receiver<Event>, stage: Stage) {
    for event in events {
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

/// Waits on `events` for the answer to `request`.
fn answer_to(events: &Receiver<Event>, request: u64) -> Answer {
    for event in events {
        if let Event::Answer {
            request: answered,
            answer,
            ..
        } = event
            && answered == request
        {
            return answer;
        }
    }
    panic!("the session stopped before answering {request}");
}

/// The function named `name`.
fn function(session: &Session, name: &str) -> FunctionId {
    session.database().unwrap().find_function(name).unwrap()
}

/// The first variable of `document`'s function printed in it that is not
/// a global.
fn a_variable(document: &Document) -> VarId {
    document
        .spans
        .iter()
        .find_map(|span| match span.node {
            Some(Node::Var(var))
                if span.kind.is_variable()
                    && !matches!(
                        document.decompiled.l2.variables[var.0 as usize].kind,
                        VarKind::Global(_)
                    ) =>
            {
                Some(var)
            }
            _ => None,
        })
        .unwrap()
}

/// Every function's C as `binbun decompile FILE [--debug DEBUG]` prints
/// it, by entry.
fn as_the_cli_prints(file: &Path, debug: Option<&Path>) -> Texts {
    let data = fs::read(file).unwrap();
    let model =
        debug.map(|debug| binbun_debuginfo::info::read(&fs::read(debug).unwrap(), &data).unwrap());
    let image = Image::parse(&data).unwrap();
    let database = Database::with_debug(&image, Seeds::ALL, model).unwrap();
    let options = DecompileOptions {
        style: Some("kr".to_owned()),
        ..DecompileOptions::default()
    };
    let mut texts = BTreeMap::new();
    database.decompile_all(
        &options,
        |output| output,
        |output| {
            let text = output.result.map(|decompiled| decompiled.c.unwrap().text);
            texts.insert(output.entry, text);
        },
    );
    texts
}

/// Each function's C (or why there is none), by entry.
type Texts = BTreeMap<u64, Result<String, String>>;

/// Every function of `session`'s database requested at once, as soon as
/// the functions are recovered (`events` at [`Stage::Analysed`]): each
/// one's C as answered, by entry; with the functions.
fn request_every_function(
    session: &Session,
    events: &Receiver<Event>,
) -> (Vec<(FunctionId, u64)>, Texts) {
    let database = session.database().unwrap();
    let functions: Vec<(FunctionId, u64)> = database
        .functions()
        .map(|(id, function)| (id, function.entry))
        .collect();
    let requests: BTreeMap<u64, u64> = functions
        .iter()
        .map(|&(id, entry)| (session.request(id), entry))
        .collect();
    let mut answered = BTreeMap::new();
    for event in events {
        if let Event::Document {
            request, result, ..
        } = event
        {
            let text = result.map(|document| document.text.clone());
            answered.insert(requests[&request], text);
            if answered.len() == requests.len() {
                break;
            }
        }
    }
    (functions, answered)
}

#[test]
fn requests_during_and_after_the_analysis_print_as_the_cli() {
    let expected = as_the_cli_prints(&binary(), None);
    let dir = project("as-the-cli");
    let session = open(&dir);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    // Asked for at once, before the cross-references are built.
    let (functions, answered) = request_every_function(&session, &events);
    assert_eq!(answered, expected);
    // After the warming, each printed again from its kept L2.
    wait_for(&events, Stage::Warmed);
    for &(id, entry) in &functions {
        let text = session.document(id).map(|document| document.text.clone());
        assert_eq!(text, expected[&entry]);
    }
    session.close();
}

/// Every function of bash, each requested on its own during the analysis
/// (what it reads of other functions found on demand, on several
/// threads, as the GUI's first requests find it), prints as the CLI's
/// whole-program stream prints it. Skipped where `/usr/bin/bash` is
/// absent.
#[test]
fn every_bash_function_requested_alone_prints_as_the_cli() {
    let path = Path::new("/usr/bin/bash");
    if !path.exists() {
        return;
    }
    let expected = as_the_cli_prints(path, None);
    let dir = project("every-bash");
    let session = Session::open(
        path,
        Options {
            project: Some(dir.to_path_buf()),
            warm: false,
            debug: DebugSource::Without,
            identity: Some(identity()),
            ..Options::default()
        },
    )
    .unwrap();
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let (_, answered) = request_every_function(&session, &events);
    assert_eq!(answered.len(), expected.len());
    let differing: Vec<String> = expected
        .iter()
        .filter(|&(entry, text)| answered.get(entry) != Some(text))
        .map(|(entry, _)| format!("{entry:#x}"))
        .collect();
    assert!(differing.is_empty(), "differ from the CLI: {differing:?}");
    session.close();
}

/// An image linked `-z now -z relro` (bash on most distributions: calls
/// through fixed import slots print as direct calls named by the import)
/// prints as the CLI does: every part of the image the printer reads is
/// the session's too; with the debug information the session found (a
/// debuginfod download), as `--debug` with that file. Skipped where
/// `/usr/bin/bash` is absent.
#[test]
fn fixed_import_slots_print_as_the_cli() {
    let path = Path::new("/usr/bin/bash");
    let Ok(data) = fs::read(path) else {
        return;
    };
    let dir = project("fixed-imports");
    let session = Session::open(
        path,
        Options {
            project: Some(dir.to_path_buf()),
            warm: false,
            identity: Some(identity()),
            ..Options::default()
        },
    )
    .unwrap();
    {
        let events = session.subscribe(None);
        wait_for(&events, Stage::Analysed);
    }
    let model = session
        .debug_file()
        .map(|debug| binbun_debuginfo::info::locate::open(debug, path, &data).unwrap());
    let image = Image::parse(&data).unwrap();
    let database = Database::with_debug(&image, Seeds::ALL, model).unwrap();
    let expected = |name: &str, view| {
        let function = database.find_function(name).unwrap();
        let options = DecompileOptions {
            style: Some("kr".to_owned()),
            view,
            ..DecompileOptions::default()
        };
        database
            .decompile(function, &options)
            .result
            .map(|decompiled| decompiled.c.unwrap().text)
    };
    for (name, view) in [
        ("xtrace_init", View::Exact),
        ("xtrace_init", View::Reading),
        ("main", View::Reading),
    ] {
        let id = session.database().unwrap().find_function(name).unwrap();
        let text = session
            .document_view(id, view)
            .map(|document| document.text.clone());
        assert_eq!(text, expected(name, view), "{name} {view:?}");
    }
    session.close();
}

#[test]
fn a_variable_renamed_prints_its_function_again_and_no_other() {
    let dir = project("variable");
    let session = open(&dir);
    let (sum, checked) = {
        let events = session.subscribe(None);
        wait_for(&events, Stage::Analysed);
        (
            function(&session, "loop_sum"),
            function(&session, "checked"),
        )
    };
    let before = session.document(sum).unwrap();
    let other = session.document(checked).unwrap();
    let var = a_variable(&before);
    let change = session.rename_variable(sum, var, Some("total")).unwrap();
    assert_eq!(change.documents, vec![sum]);
    assert_eq!(change.listing, Vec::new());
    let after = session.document(sum).unwrap();
    assert!(after.text.contains("total"), "{}", after.text);
    assert_ne!(after.text, before.text);
    assert!(Arc::ptr_eq(&session.document(checked).unwrap(), &other));
    // Its L2 kept, not decompiled again.
    assert!(Arc::ptr_eq(&after.decompiled, &before.decompiled));
    // Named back: the first print again.
    session.rename_variable(sum, var, None).unwrap();
    assert_eq!(session.document(sum).unwrap().text, before.text);
    session.close();
}

#[test]
fn a_globals_table_names_its_type_as_its_declaration_does() {
    let dir = project("global-table");
    let session = open(&dir);
    {
        let events = session.subscribe(None);
        wait_for(&events, Stage::Callers);
    }
    let starts: Vec<u64> = {
        let database = session.database().unwrap();
        let callers = database.known_callers(&[]).unwrap();
        callers.schemes.globals().iter().map(|(at, _)| at).collect()
    };
    // The fixture's: pointers to code and data, a byte.
    assert_eq!(starts.len(), 8);
    let squeezed = |text: &str| text.split_whitespace().collect::<String>();
    for start in starts {
        let typed = session.global_type(start).unwrap();
        let table = session.global_table(start).unwrap();
        let declared = typed.c.as_deref().unwrap().replacen(&typed.name, "", 1);
        let named = table.names[table.ty.0 as usize].as_deref().unwrap();
        assert_eq!(squeezed(named), squeezed(&declared), "{:?}", typed.c);
        assert_eq!(table.types.width(table.ty), Some(typed.ty.size * 8));
    }
    session.close();
}

#[test]
fn each_view_is_kept_apart_and_defaults_are_the_unnamed_print() {
    let dir = project("views");
    let session = open(&dir);
    let sum = {
        let events = session.subscribe(None);
        wait_for(&events, Stage::Analysed);
        function(&session, "loop_sum")
    };
    let exact = session.document_view(sum, View::Exact).unwrap();
    let reading = session.document_view(sum, View::Reading).unwrap();
    assert_eq!(exact.text, session.document(sum).unwrap().text);
    assert!(!Arc::ptr_eq(&exact.decompiled, &reading.decompiled));
    // Renamed in the reading view: both views print the name (it names what
    // the variable was made from), the defaults stay the printer's.
    let var = a_variable(&reading);
    let default = reading.default_name(var).unwrap().to_owned();
    let change = session
        .rename_variable_in(sum, View::Reading, var, Some("total"))
        .unwrap();
    assert_eq!(change.documents, vec![sum]);
    let renamed = session.document_view(sum, View::Reading).unwrap();
    assert!(renamed.text.contains("total"), "{}", renamed.text);
    assert_eq!(renamed.default_name(var), Some(default.as_str()));
    assert!(Arc::ptr_eq(&renamed.decompiled, &reading.decompiled));
    let exact_after = session.document_view(sum, View::Exact).unwrap();
    assert!(exact_after.text.contains("total"), "{}", exact_after.text);
    assert!(Arc::ptr_eq(&exact_after.decompiled, &exact.decompiled));
    session.close();
}

#[test]
fn a_function_renamed_prints_its_callers_again() {
    let dir = project("function");
    let session = open(&dir);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let classify = function(&session, "classify");
    let checked = function(&session, "checked");
    let sum = function(&session, "loop_sum");
    let entry = session
        .database()
        .unwrap()
        .function(classify)
        .unwrap()
        .entry;
    let caller = session.document(checked).unwrap();
    let unrelated = session.document(sum).unwrap();
    let changes = Arc::new(Mutex::new(Vec::new()));
    {
        let changes = Arc::clone(&changes);
        session.on_event(move |event| {
            if let Event::Changed(change) = event {
                changes.lock().unwrap().push(Arc::clone(change));
            }
        });
    }
    let change = session.rename_function(entry, Some("bucket")).unwrap();
    assert!(change.documents.contains(&checked), "{change:?}");
    assert!(change.documents.contains(&classify), "{change:?}");
    assert!(!change.documents.contains(&sum), "{change:?}");
    assert!(change.listing.iter().any(|range| range.contains(&entry)));
    assert_eq!(*changes.lock().unwrap(), vec![Arc::clone(&change)]);
    let after = session.document(checked).unwrap();
    assert!(after.text.contains("bucket("), "{}", after.text);
    assert!(!after.text.contains("classify("), "{}", after.text);
    assert_ne!(after.text, caller.text);
    assert!(session.document(classify).unwrap().text.contains("bucket("));
    assert!(Arc::ptr_eq(&session.document(sum).unwrap(), &unrelated));
    assert_eq!(session.name(entry).as_deref(), Some("bucket"));
    session.close();
}

#[test]
fn a_style_set_prints_the_documents_printed_again_and_nothing_else() {
    let dir = project("style");
    let session = open(&dir);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let sum = function(&session, "loop_sum");
    let checked = function(&session, "checked");
    let fixed = session.document(sum).unwrap();
    assert!(fixed.text.contains("int64_t"), "{}", fixed.text);
    let style = session.style();
    assert_eq!(style.int_spelling, IntSpelling::Fixed);
    let plain = style.with_int_spelling(IntSpelling::Plain);
    let change = session.set_style(plain);
    // Only what was printed prints again; `checked` was never asked for.
    assert_eq!(change.documents, vec![sum]);
    assert_eq!(session.style(), plain);
    let after = session.document(sum).unwrap();
    assert!(!after.text.contains("int64_t"), "{}", after.text);
    assert!(after.text.contains("int checked(long);"), "{}", after.text);
    // Printed again, not decompiled again.
    assert!(Arc::ptr_eq(&after.decompiled, &fixed.decompiled));
    assert!(!session.document(checked).unwrap().text.contains("int32_t"));
    // The style it has already: nothing changes.
    assert_eq!(session.set_style(plain).documents, Vec::new());
    assert!(Arc::ptr_eq(&session.document(sum).unwrap(), &after));
    // Back: the first print.
    session.set_style(style);
    assert_eq!(session.document(sum).unwrap().text, fixed.text);
    session.close();
}

#[test]
fn a_session_opened_with_plain_types_prints_them_from_the_start() {
    let dir = project("style-open");
    let session = Session::open(
        binary(),
        Options {
            project: Some(dir.to_owned()),
            identity: Some(identity()),
            types: IntSpelling::Plain,
            ..Options::default()
        },
    )
    .unwrap();
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let sum = function(&session, "loop_sum");
    let text = session.document(sum).unwrap().text.clone();
    assert!(text.contains("int checked(long);"), "{text}");
    assert!(
        !text.contains("int64_t") && !text.contains("int32_t"),
        "{text}"
    );
    session.close();
}

/// The variable printed as `name` in `document`.
fn named(document: &Document, name: &str) -> VarId {
    document
        .spans
        .iter()
        .find_map(|span| match span.node {
            Some(Node::Var(var))
                if span.kind.is_variable()
                    && document.text.get(span.range.clone()) == Some(name) =>
            {
                Some(var)
            }
            _ => None,
        })
        .unwrap()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one session's edits, saved and reopened"
)]
fn a_prototype_typed_decompiles_its_function_and_callers_again_and_is_saved() {
    let path = project("types");
    let (classify_text, checked_text, sum_text) = {
        let session = open(&path);
        let events = session.subscribe(None);
        wait_for(&events, Stage::Analysed);
        let classify = function(&session, "classify");
        let checked = function(&session, "checked");
        let sum = function(&session, "loop_sum");
        let entry = session
            .database()
            .unwrap()
            .function(classify)
            .unwrap()
            .entry;
        let before = session.document(checked).unwrap();
        assert!(
            before.text.contains("int32_t classify(int64_t);"),
            "{}",
            before.text
        );
        let unrelated = session.document(sum).unwrap();
        // Refused C changes nothing and says where.
        let refused = session
            .set_type(
                Typed::Prototype(entry),
                Some("unsigned classify(mystery_t v)"),
            )
            .unwrap_err();
        let Error::Type(error) = refused else {
            panic!("{refused:?}");
        };
        assert_eq!(error.span, 18..27);
        let change = session
            .set_type(
                Typed::Prototype(entry),
                Some("unsigned int classify(unsigned int value)"),
            )
            .unwrap();
        assert!(change.documents.contains(&classify), "{change:?}");
        assert!(change.documents.contains(&checked), "{change:?}");
        assert!(!change.documents.contains(&sum), "{change:?}");
        let own = session.document(classify).unwrap().text.clone();
        assert!(own.contains("uint32_t classify(uint32_t value)"), "{own}");
        let caller = session.document(checked).unwrap();
        assert!(
            caller.text.contains("uint32_t classify(uint32_t);"),
            "{}",
            caller.text
        );
        assert!(
            !Arc::ptr_eq(&caller.decompiled, &before.decompiled),
            "decompiled again"
        );
        assert!(Arc::ptr_eq(&session.document(sum).unwrap(), &unrelated));
        // A local of loop_sum typed: a declared bound, printed so.
        let result = named(&unrelated, "result");
        let variable = session.variable(sum, View::Exact, result).unwrap();
        // A type of another width would be dropped by decompilation:
        // refused, naming both sizes.
        let refused = session
            .set_type(Typed::Variable(variable.clone()), Some("char *"))
            .unwrap_err();
        let Error::Type(error) = refused else {
            panic!("{refused:?}");
        };
        assert_eq!(
            (error.message.as_str(), error.span),
            ("the variable is 4 bytes; the type is 8 bytes", 0..6)
        );
        assert!(Arc::ptr_eq(&session.document(sum).unwrap(), &unrelated));
        let change = session
            .set_type(Typed::Variable(variable), Some("unsigned int"))
            .unwrap();
        assert_eq!(change.documents, vec![sum]);
        let typed = session.document(sum).unwrap().text.clone();
        assert!(typed.contains("uint32_t result = 0;"), "{typed}");
        let why = session.ask(sum, View::Exact, Question::Explain);
        let Answer::Explained(Ok(explanation)) = answer_to(&events, why.request) else {
            panic!("no explanation");
        };
        let item = explanation
            .items
            .iter()
            .find(|item| item.name == "result")
            .unwrap();
        assert_eq!(item.source, binbun::queries::evidence::Source::User);
        session.close();
        (own, caller.text.clone(), typed)
    };
    let saved = fs::read_to_string(path.join("project.toml")).unwrap();
    assert!(saved.contains("[[type]]"), "{saved}");
    assert!(
        saved.contains("unsigned int classify(unsigned int value)"),
        "{saved}"
    );
    let session = open(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let text = |name: &str| {
        session
            .document(function(&session, name))
            .unwrap()
            .text
            .clone()
    };
    assert_eq!(text("classify"), classify_text);
    assert_eq!(text("checked"), checked_text);
    assert_eq!(text("loop_sum"), sum_text);
    // Typed back: as analysis types it again.
    let entry = session
        .database()
        .unwrap()
        .function(function(&session, "classify"))
        .unwrap()
        .entry;
    session.set_type(Typed::Prototype(entry), None).unwrap();
    assert!(text("checked").contains("int32_t classify(int64_t);"));
    assert_eq!(session.unresolved(), Vec::new());
    session.close();
}

#[test]
fn bookmarks_are_saved_listed_and_removed() {
    let path = project("bookmarks");
    let (at, other) = {
        let session = open(&path);
        let events = session.subscribe(None);
        wait_for(&events, Stage::Analysed);
        let sum = function(&session, "loop_sum");
        let checked = function(&session, "checked");
        let database = session.database().unwrap();
        let at = database.function(sum).unwrap().entry;
        let other = database.function(checked).unwrap().entry;
        // A bookmark changes only its listing line: no C prints again.
        let change = session.bookmark(at, Some("the loop")).unwrap();
        assert_eq!(change.documents, Vec::<FunctionId>::new());
        assert_eq!(change.listing, vec![at..at + 1]);
        session.bookmark(other, Some("gone soon")).unwrap();
        session.bookmark(other, None).unwrap();
        // Empty: no bookmark.
        session.bookmark(other + 1, Some("")).unwrap();
        session.close();
        (at, other)
    };
    let saved = fs::read_to_string(path.join("project.toml")).unwrap();
    assert!(
        saved.contains("[[bookmark]]") && saved.contains("name = \"the loop\""),
        "{saved}"
    );
    let session = open(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let edits = session.edits();
    assert_eq!(edits.bookmark(at), Some("the loop"));
    assert_eq!(edits.bookmark(other), None);
    assert_eq!(edits.bookmarks().len(), 1);
    assert!(edits.all().any(|edit| edit
        == Edit::Bookmark {
            address: at,
            name: "the loop".to_owned()
        }));
    assert_eq!(session.unresolved(), Vec::new());
    session.close();
}

#[test]
fn a_document_made_on_the_calling_thread_is_the_workers() {
    let path = project("here");
    let session = open(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let sum = function(&session, "loop_sum");
    let here = session.document_here(sum, View::Exact).unwrap();
    // Kept: the worker answers with the same document.
    let asked = session.document_view(sum, View::Exact).unwrap();
    assert!(Arc::ptr_eq(&here, &asked));
    session.close();
}

#[test]
fn the_users_version_of_a_synthesised_struct_replaces_it_and_is_saved() {
    let path = project("struct");
    let start_text = {
        let session = open(&path);
        let events = session.subscribe(None);
        wait_for(&events, Stage::Analysed);
        let start = function(&session, "_start");
        let before = session.document(start).unwrap().text.clone();
        assert!(before.contains("v6->field_0 = v5;"), "{before}");
        let listed = session.synthesised().unwrap();
        let found = listed
            .iter()
            .find(|s| s.key == "struct struct__start_1")
            .unwrap_or_else(|| panic!("{listed:?}"));
        assert_eq!((found.size, found.stated), (16, false));
        assert_eq!(
            found.c,
            "struct struct__start_1 {\n    void *field_0;\n    int64_t field_8;\n};"
        );
        let typed = found.typed();
        // A struct that does not parse is refused where it fails.
        let refused = session
            .set_type(
                typed.clone(),
                Some("struct frame { void *top; argc_t n; };"),
            )
            .unwrap_err();
        let Error::Type(error) = refused else {
            panic!("{refused:?}");
        };
        assert_eq!(error.span, 26..32);
        let change = session
            .set_type(typed, Some("struct frame { void *top; long argc; };"))
            .unwrap();
        assert!(change.documents.contains(&start), "{change:?}");
        let after = session.document(start).unwrap().text.clone();
        assert!(after.contains("struct frame *v6 = "), "{after}");
        assert!(after.contains("v6->top = v5;"), "{after}");
        assert!(!after.contains("struct__start_1"), "{after}");
        let listed = session.synthesised().unwrap();
        let found = listed
            .iter()
            .find(|s| s.key == "struct frame")
            .unwrap_or_else(|| panic!("{listed:?}"));
        assert!(found.stated);
        session.close();
        after
    };
    let saved = fs::read_to_string(path.join("project.toml")).unwrap();
    assert!(saved.contains("struct = 1"), "{saved}");
    let session = open(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let start = function(&session, "_start");
    assert_eq!(session.document(start).unwrap().text, start_text);
    assert_eq!(session.unresolved(), Vec::new());
    session.close();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one session's member edits, saved and reopened"
)]
fn a_member_renamed_or_retyped_reaches_every_function_using_its_struct_and_is_saved() {
    let path = project("members");
    let names = ["fail", "checked", "_start"];
    let texts = {
        let session = open(&path);
        let events = session.subscribe(None);
        wait_for(&events, Stage::Analysed);
        let [fail, checked, start] = names.map(|name| function(&session, name));
        let entry = |f| session.database().unwrap().function(f).unwrap().entry;
        let text = |f| session.document(f).unwrap().text.clone();
        // A struct of the user's that two functions take.
        session
            .define("struct pair {\n    char *key;\n    int32_t small;\n    int64_t count;\n};")
            .unwrap();
        session
            .set_type(
                Typed::Prototype(entry(fail)),
                Some("void fail(struct pair *p)"),
            )
            .unwrap();
        session
            .set_type(
                Typed::Prototype(entry(checked)),
                Some("int32_t checked(struct pair *p)"),
            )
            .unwrap();
        for f in [fail, checked] {
            assert!(text(f).contains("    char *key;"), "{}", text(f));
        }
        let change = session
            .edit_member("struct pair", "key", &MemberEdit::Rename("name".to_owned()))
            .unwrap();
        for f in [fail, checked] {
            assert!(change.documents.contains(&f), "{change:?}");
            let now = text(f);
            assert!(
                now.contains("    char *name;") && !now.contains("key"),
                "{now}"
            );
        }
        session
            .edit_member(
                "struct pair",
                "count",
                &MemberEdit::Retype("uint64_t".to_owned()),
            )
            .unwrap();
        for f in [fail, checked] {
            assert!(text(f).contains("    uint64_t count;"), "{}", text(f));
        }
        // A retype to another width is refused; nothing changes.
        let (edits, before) = (session.edits(), text(fail));
        for (member, ty) in [("count", "char"), ("small", "int64_t")] {
            let refused = session
                .edit_member("struct pair", member, &MemberEdit::Retype(ty.to_owned()))
                .unwrap_err();
            assert!(matches!(refused, Error::Type(_)), "{refused:?}");
        }
        assert_eq!(session.edits(), edits);
        assert_eq!(text(fail), before);
        // A resize (`D`) may take the unused bytes up to the next member.
        session
            .edit_member(
                "struct pair",
                "small",
                &MemberEdit::Resize("int64_t".to_owned()),
            )
            .unwrap();
        assert!(text(fail).contains("    int64_t small;"), "{}", text(fail));
        // A synthesised struct's member, renamed from its use: the user's
        // version, the use printed with the new name, known as the
        // member's and standing for the access.
        assert!(text(start).contains("v6->field_0 = v5;"), "{}", text(start));
        session
            .edit_member(
                "struct struct__start_1",
                "field_0",
                &MemberEdit::Rename("top".to_owned()),
            )
            .unwrap();
        let document = session.document(start).unwrap();
        assert!(document.text.contains("v6->top = v5;"), "{}", document.text);
        let uses: Vec<usize> = document
            .members
            .keys()
            .copied()
            .filter(|&s| document.text.get(document.spans[s].range.clone()) == Some("top"))
            .collect();
        // Its line in the definition and its use.
        assert_eq!(uses.len(), 2, "{:?}", document.members);
        let of: Vec<_> = uses.iter().map(|s| document.members[s]).collect();
        assert_eq!(of[0], of[1]);
        assert!(matches!(
            document.spans[uses[1]].node,
            Some(Node::Expr(_) | Node::Stmt(_))
        ));
        assert_eq!(
            document.spans[uses[1]].node,
            document.spans[uses[1] - 1].node
        );
        let texts = [fail, checked, start].map(text);
        session.close();
        texts
    };
    let saved = fs::read_to_string(path.join("project.toml")).unwrap();
    assert!(saved.contains("char *name;"), "{saved}");
    let session = open(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    for (name, before) in names.iter().zip(&texts) {
        let f = function(&session, name);
        assert_eq!(&session.document(f).unwrap().text, before);
    }
    assert_eq!(session.unresolved(), Vec::new());
    session.close();
}

/// A session on the variadic fixture (`report` hands its `FILE *` to
/// `vfprintf`, whose libc prototype names `struct _IO_FILE`) with the
/// project file at `project`.
fn open_variadic(project: &Path) -> Session {
    let binary =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/variadic-gcc-x86_64.elf");
    Session::open(
        binary,
        Options {
            project: Some(project.to_owned()),
            identity: Some(identity()),
            ..Options::default()
        },
    )
    .unwrap()
}

#[test]
fn a_redefined_library_struct_replaces_the_librarys_and_is_saved() {
    let path = project("library-struct");
    let redefined = {
        let session = open_variadic(&path);
        let events = session.subscribe(None);
        wait_for(&events, Stage::Analysed);
        let report = function(&session, "report");
        let before = session.document(report).unwrap().text.clone();
        assert!(before.contains("    char *_IO_read_ptr;"), "{before}");
        // As the in-place edit of the printed definition applies it.
        let (key, change) = session
            .define(
                "struct _IO_FILE {\n    int32_t flags;\n    int32_t mode;\n    char *read_ptr;\n};",
            )
            .unwrap();
        assert_eq!(key, "struct _IO_FILE");
        assert!(change.documents.contains(&report), "{change:?}");
        let after = session.document(report).unwrap().text.clone();
        assert!(
            after.contains(
                "struct _IO_FILE {\n    int32_t flags;\n    int32_t mode;\n    char *read_ptr;\n} __attribute__((packed));"
            ),
            "{after}"
        );
        assert!(!after.contains("_IO_read_ptr"), "{after}");
        assert!(
            after.contains("int32_t vfprintf(struct _IO_FILE *, char *, va_list);"),
            "{after}"
        );
        session.close();
        after
    };
    let session = open_variadic(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let report = function(&session, "report");
    assert_eq!(session.document(report).unwrap().text, redefined);
    assert_eq!(session.unresolved(), Vec::new());
    // Without the user's definition the library's is the type again.
    let change = session.undefine("struct _IO_FILE").unwrap();
    assert!(change.documents.contains(&report), "{change:?}");
    let restored = session.document(report).unwrap().text.clone();
    assert!(restored.contains("    char *_IO_read_ptr;"), "{restored}");
    assert!(!restored.contains("read_ptr;\n};"), "{restored}");
    session.close();
}

#[test]
fn enumerations_are_listed_laid_out_and_their_c_reads_back() {
    let path = project("enumerations");
    let session = open_variadic(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let perm = "enum __attribute__((flag_enum)) perm : uint8_t { X = 1, W = 2, R = 4 };";
    assert_eq!(
        session.type_layout(perm).unwrap(),
        TypeLayout::Enum(EnumLayout {
            key: "enum perm".to_owned(),
            size: 1,
            flags: true,
            constants: vec![
                ("X".to_owned(), 1),
                ("W".to_owned(), 2),
                ("R".to_owned(), 4)
            ],
        })
    );
    // Laying it out defines nothing.
    let listed = session.enumerations();
    assert!(listed.iter().all(|(name, _)| name != "enum perm"));
    // Each of the library's prints as C that lays out as it is listed.
    let library = listed
        .iter()
        .find(|(_, e)| e.constants.len() > 1 && e.name.is_some())
        .expect("an enumeration in the library");
    let c = session.definition_text(&library.0).unwrap();
    let Ok(TypeLayout::Enum(laid)) = session.type_layout(&c) else {
        panic!("{c} lays out no enumeration");
    };
    assert_eq!(laid.size * 8, u64::from(library.1.width), "{c}");
    let names: Vec<&str> = laid.constants.iter().map(|(n, _)| n.as_str()).collect();
    let listed_names: Vec<&str> = library
        .1
        .constants
        .iter()
        .map(|(n, _)| n.as_str())
        .collect();
    assert_eq!(names, listed_names, "{c}");
    // Defined, the user's is listed with its constants.
    session.define(perm).unwrap();
    let (_, defined) = session
        .enumerations()
        .into_iter()
        .find(|(name, _)| name == "enum perm")
        .unwrap();
    assert!(defined.flags && defined.width == 8);
    assert_eq!(defined.named(6).unwrap().names, ["W", "R"]);
    session.close();
}

#[test]
fn edits_survive_saving_and_reopening() {
    let path = project("reopen");
    let (sum_text, comment_at) = {
        let session = open(&path);
        let events = session.subscribe(None);
        wait_for(&events, Stage::Analysed);
        let sum = function(&session, "loop_sum");
        let checked = function(&session, "checked");
        let database = session.database().unwrap();
        let entry = database.function(checked).unwrap().entry;
        let comment_at = database.function(sum).unwrap().entry + 1;
        let document = session.document(sum).unwrap();
        session
            .rename_variable(sum, a_variable(&document), Some("total"))
            .unwrap();
        session.rename_function(entry, Some("bucket")).unwrap();
        session
            .comment(comment_at, Some("sums \"checked\"\nover n"))
            .unwrap();
        let text = session.document(sum).unwrap().text.clone();
        session.close();
        (text, comment_at)
    };
    let saved = fs::read_to_string(path.join("project.toml")).unwrap();
    assert!(saved.contains("[[variable]]"), "{saved}");
    assert!(saved.contains("name = \"bucket\""), "{saved}");
    assert!(!path.join("project.toml.tmp").exists());
    let session = open(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let sum = function(&session, "loop_sum");
    assert_eq!(session.document(sum).unwrap().text, sum_text);
    assert!(
        sum_text.contains("total") && sum_text.contains("bucket("),
        "{sum_text}"
    );
    assert_eq!(
        session.edits().comment(comment_at),
        Some("sums \"checked\"\nover n")
    );
    assert_eq!(session.unresolved(), Vec::new());
    session.close();
}

/// The first literal of `document` that is a number written in decimal,
/// its text and an instruction its line's expressions and statements came
/// from (literals have no provenance of their own).
fn a_number(document: &Document) -> Option<(String, u64)> {
    document.spans.iter().find_map(|span| {
        let text = document.text.get(span.range.clone())?;
        if span.kind != TokenKind::Number || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let address = line_instructions(document, span.range.start)
            .first()
            .copied();
        address.map(|address| (text.to_owned(), address))
    })
}

/// The instructions the expressions and statements of the line holding
/// byte `at` of `document` came from, in the line's order.
fn line_instructions(document: &Document, at: usize) -> Vec<u64> {
    let l2 = &document.decompiled.l2;
    let l1 = &document.decompiled.l1;
    let start = document.text[..at].rfind('\n').map_or(0, |n| n + 1);
    let end = document.text[at..]
        .find('\n')
        .map_or(document.text.len(), |n| at + n);
    document
        .spans
        .iter()
        .filter(|other| (start..end).contains(&other.range.start))
        .flat_map(|other| match other.node {
            Some(Node::Expr(expr)) => l2.provenance.expr(expr),
            Some(Node::Stmt(stmt)) => l2.provenance.stmt(stmt),
            Some(Node::Var(_) | Node::Type(_)) | None => &[],
        })
        .filter_map(|origin| match *origin {
            Origin::Instruction(address) => Some(address),
            Origin::Value(value) => {
                match l1.values.get(usize::try_from(value.0).ok()?)?.definition {
                    Definition::Result { inst, .. } => l1.inst(inst).map(|i| i.address),
                    Definition::Parameter { .. } => None,
                }
            }
            Origin::Register(_)
            | Origin::Held(_)
            | Origin::Slot(_)
            | Origin::Block(_)
            | Origin::Absorbed(_)
            | Origin::Proved => None,
        })
        .collect()
}

#[test]
fn a_number_written_in_another_form_prints_its_function_so_and_is_saved() {
    let path = project("number");
    let session = open(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let (function, before, text, address) = session
        .database()
        .unwrap()
        .functions()
        .map(|(id, _)| id)
        .collect::<Vec<_>>()
        .into_iter()
        .find_map(|id| {
            let document = session.document(id).ok()?;
            let (text, address) = a_number(&document)?;
            Some((id, document, text, address))
        })
        .expect("a function with a decimal literal from an instruction");
    let value: u64 = text.parse().unwrap();
    let change = session
        .number(address, value, Some(NumberForm::Hex))
        .unwrap();
    assert!(change.documents.contains(&function), "{change:?}");
    assert!(change.listing.iter().any(|range| range.contains(&address)));
    let after = session.document(function).unwrap();
    let hex = format!("0x{value:x}");
    assert!(after.text.contains(&hex), "{hex} in {}", after.text);
    assert!(Arc::ptr_eq(&after.decompiled, &before.decompiled));
    // Every span still covers its token.
    for span in &after.spans {
        assert!(after.text.get(span.range.clone()).is_some());
    }
    session.close();
    let saved = fs::read_to_string(path.join("project.toml")).unwrap();
    assert!(
        saved.contains("[[number]]") && saved.contains("form = \"hex\""),
        "{saved}"
    );
    let session = open(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    assert_eq!(session.document(function).unwrap().text, after.text);
    // Back to the printer's form: the first print again.
    session.number(address, value, None).unwrap();
    assert_eq!(session.document(function).unwrap().text, before.text);
    session.close();
}

/// The line of `document` holding byte `at`, and its text.
fn line_at(document: &Document, at: usize) -> (usize, &str) {
    let n = document.text[..at].matches('\n').count();
    (n, document.text.split('\n').nth(n).unwrap())
}

/// The first line of `document` made from two instructions or more: a
/// byte on it and its two lowest instructions.
fn a_line_of_two_instructions(document: &Document) -> (usize, u64, u64) {
    document
        .spans
        .iter()
        .filter(|span| matches!(span.node, Some(Node::Stmt(_))))
        .find_map(|span| {
            let mut instructions = line_instructions(document, span.range.start);
            instructions.sort_unstable();
            instructions.dedup();
            match instructions[..] {
                [first, second, ..] => Some((span.range.start, first, second)),
                _ => None,
            }
        })
        .unwrap()
}

#[test]
fn comments_print_at_the_end_of_their_lines_and_survive_renames_and_retypes() {
    let path = project("comments");
    let session = open(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let sum = function(&session, "loop_sum");
    let checked = function(&session, "checked");
    let before = session.document(sum).unwrap();
    let other = session.document(checked).unwrap();
    assert!(before.comments.is_empty());
    let (at, first, second) = a_line_of_two_instructions(&before);
    let (n, line) = line_at(&before, at);
    let line = line.to_owned();
    // Printed once, at the end of its line, `*/` unable to end it early;
    // re-printed, not decompiled again, and no other function.
    let change = session.comment(second, Some("the sum */ so far")).unwrap();
    assert_eq!(change.documents, vec![sum]);
    assert!(change.listing.iter().any(|range| range.contains(&second)));
    let after = session.document(sum).unwrap();
    assert!(Arc::ptr_eq(&after.decompiled, &before.decompiled));
    assert!(Arc::ptr_eq(&session.document(checked).unwrap(), &other));
    assert_eq!(
        after.text.split('\n').nth(n).unwrap(),
        format!("{line} /* the sum * / so far */")
    );
    assert_eq!(after.text.matches("/* the sum").count(), 1);
    let (&span, commented) = after.comments.iter().next().unwrap();
    assert_eq!(
        (after.comments.len(), commented),
        (1, &(second, "the sum */ so far".to_owned()))
    );
    assert_eq!(after.spans[span].kind, TokenKind::Comment);
    assert_eq!(
        &after.text[after.spans[span].range.clone()],
        "/* the sum * / so far */"
    );
    for span in &after.spans {
        assert!(after.text.get(span.range.clone()).is_some());
    }
    // A line made from two commented instructions: their comments in
    // address order, a comment of two lines as two lines, the second
    // under the first.
    session.comment(second, Some("then")).unwrap();
    session.comment(first, Some("one\ntwo")).unwrap();
    let both = session.document(sum).unwrap();
    let column = " ".repeat(line.chars().count() + 1);
    let lines: Vec<&str> = both.text.split('\n').skip(n).take(3).collect();
    assert_eq!(
        lines,
        [
            format!("{line} /* one */"),
            format!("{column}/* two */"),
            format!("{column}/* then */"),
        ]
    );
    let commented: Vec<&(u64, String)> = both.comments.values().collect();
    assert_eq!(
        commented,
        [
            &(first, "one".to_owned()),
            &(first, "two".to_owned()),
            &(second, "then".to_owned()),
        ]
    );
    // Survives a rename (printed again) and a retype (decompiled again).
    let result = named(&both, "result");
    session.rename_variable(sum, result, Some("total")).unwrap();
    let renamed = session.document(sum).unwrap();
    assert!(renamed.text.contains("total"), "{}", renamed.text);
    assert!(renamed.text.contains("/* one */"), "{}", renamed.text);
    assert_eq!(renamed.comments.len(), 3);
    let variable = session.variable(sum, View::Exact, result).unwrap();
    session
        .set_type(Typed::Variable(variable), Some("unsigned int"))
        .unwrap();
    let typed = session.document(sum).unwrap();
    assert!(!Arc::ptr_eq(&typed.decompiled, &renamed.decompiled));
    assert!(typed.text.contains("uint32_t total = 0;"), "{}", typed.text);
    let commented: Vec<&(u64, String)> = typed.comments.values().collect();
    assert_eq!(
        commented,
        [
            &(first, "one".to_owned()),
            &(first, "two".to_owned()),
            &(second, "then".to_owned()),
        ]
    );
    // The reading view prints them too.
    let reading = session.document_view(sum, View::Reading).unwrap();
    assert!(reading.text.contains("/* then */"), "{}", reading.text);
    session.close();
    // Saved, and printed so on reopening.
    let session = open(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let reopened = session.document(sum).unwrap();
    assert_eq!(reopened.text, typed.text);
    // Removed: the C without them is the first print, renamed and typed.
    session.comment(first, None).unwrap();
    session.comment(second, Some("")).unwrap();
    let removed = session.document(sum).unwrap();
    assert!(removed.comments.is_empty());
    let total = named(&removed, "total");
    let variable = session.variable(sum, View::Exact, total).unwrap();
    session.rename_variable(sum, total, None).unwrap();
    session.set_type(Typed::Variable(variable), None).unwrap();
    assert_eq!(session.document(sum).unwrap().text, before.text);
    session.close();
}

/// In `exceptions-x86_64.elf`, `guarded`'s catch returns -1: `mov eax,
/// 0FFFFFFFFh` at 0x1129 in the listing, `result = -1;` in the C, the
/// operator `-` and the literal `1`. One number: a form chosen on either
/// is the other's.
#[test]
fn a_form_chosen_on_the_cs_minus_one_is_the_listings_0ffffffffh_and_back() {
    const GUARDED: u64 = 0x1280;
    const MOV: u64 = 0x1129;
    let path = project("minus-one");
    let session = Session::open(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/exceptions-x86_64.elf"),
        Options {
            project: Some(path.to_path_buf()),
            identity: Some(identity()),
            ..Options::default()
        },
    )
    .unwrap();
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    let guarded = session
        .database()
        .unwrap()
        .functions()
        .find(|(_, function)| function.entry == GUARDED)
        .map(|(id, _)| id)
        .unwrap();
    let before = session.document(guarded).unwrap();
    let text = |document: &Document, span: &binbun_print::layout::Span| {
        document.text[span.range.clone()].to_owned()
    };
    // The `-` ending where the `1` starts, on the line from the `mov`.
    let signed = |document: &Document| {
        document
            .spans
            .windows(2)
            .find(|pair| {
                pair[0].kind == TokenKind::Operator
                    && text(document, &pair[0]) == "-"
                    && pair[1].kind == TokenKind::Number
                    && pair[0].range.end == pair[1].range.start
                    && line_instructions(document, pair[1].range.start).contains(&MOV)
            })
            .map(|pair| (text(document, &pair[0]), text(document, &pair[1])))
    };
    assert_eq!(
        signed(&before),
        Some(("-".to_owned(), "1".to_owned())),
        "{}",
        before.text
    );

    // C to listing: the C's number is -1 (all its bits), the listing's
    // `0FFFFFFFFh` of the 32-bit `mov` looks it up by its own bits.
    session
        .number(MOV, u64::MAX, Some(NumberForm::Hex))
        .unwrap();
    assert_eq!(
        session.edits().number(MOV, 0xffff_ffff),
        Some(NumberForm::Hex)
    );
    // The form spells the whole number: its sign is the `-` already there.
    let hex = session.document(guarded).unwrap();
    assert_eq!(
        signed(&hex),
        Some(("-".to_owned(), "0x1".to_owned())),
        "{}",
        hex.text
    );
    assert!(!hex.text.contains("--"), "{}", hex.text);

    // Listing to C: a form chosen on `0FFFFFFFFh` writes the C's `-1`,
    // in place of the form chosen on the C's.
    session
        .number(MOV, 0xffff_ffff, Some(NumberForm::Decimal))
        .unwrap();
    assert_eq!(
        session.edits().numbers().keys().collect::<Vec<_>>(),
        [&(MOV, 0xffff_ffff)]
    );
    assert_eq!(
        session.edits().number(MOV, u64::MAX),
        Some(NumberForm::Decimal)
    );
    assert_eq!(session.document(guarded).unwrap().text, before.text);
    session
        .number(MOV, 0xffff_ffff, Some(NumberForm::Hex))
        .unwrap();
    assert_eq!(session.document(guarded).unwrap().text, hex.text);
    // Back to the printer's form from the C: no form at either width.
    session.number(MOV, u64::MAX, None).unwrap();
    assert!(session.edits().numbers().is_empty());
    assert_eq!(session.document(guarded).unwrap().text, before.text);
    session.close();
}

#[test]
fn edits_that_no_longer_resolve_are_kept_and_reported() {
    let path = project("unresolved");
    let entry = {
        let data = fs::read(binary()).unwrap();
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let sum = database.find_function("loop_sum").unwrap();
        database.function(sum).unwrap().entry
    };
    let text = format!(
        "format = 1\n\n[[function]]\naddress = \"0x1\"\nname = \"gone\"\n\n\
         [[variable]]\nfunction = \"{entry:#x}\"\norigins = [\"value 999999\"]\nname = \"lost\"\n"
    );
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("project.toml"), &text).unwrap();
    let session = open(&path);
    let events = session.subscribe(None);
    // Reported as the functions are recovered: before the stage is told,
    // or, to a subscriber that comes after, as it subscribes.
    let mut reported = Vec::new();
    for event in &events {
        match event {
            Event::Unresolved(unresolved) => reported.extend(unresolved.iter().cloned()),
            Event::Stage(stage) if stage >= Stage::Analysed => break,
            Event::Stage(_)
            | Event::Progress { .. }
            | Event::Changed(_)
            | Event::Document { .. }
            | Event::Failed(_)
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
    reported.extend(unresolved_told(&events));
    assert!(
        matches!(&reported[..], [one] if one.edit == Edit::Function { entry: 1, name: "gone".to_owned() }),
        "{reported:?}"
    );
    let sum = function(&session, "loop_sum");
    let document = session.document(sum).unwrap();
    assert_eq!(document.unresolved.len(), 1);
    assert!(!document.text.contains("lost"));
    assert_eq!(session.unresolved().len(), 2);
    // Kept: saved again with a new edit, both still there.
    session.comment(entry, Some("kept")).unwrap();
    session.close();
    let saved = fs::read_to_string(path.join("project.toml")).unwrap();
    assert!(
        saved.contains("gone") && saved.contains("value 999999"),
        "{saved}"
    );
}

/// The edits `events` has told do not resolve, of those waiting there.
fn unresolved_told(events: &Receiver<Event>) -> Vec<Unresolved> {
    events
        .try_iter()
        .flat_map(|event| match event {
            Event::Unresolved(found) => found.to_vec(),
            Event::Stage(_)
            | Event::Progress { .. }
            | Event::Changed(_)
            | Event::Document { .. }
            | Event::Failed(_)
            | Event::Symbols(_)
            | Event::Answer { .. }
            | Event::History(_)
            | Event::Conflicts(_)
            | Event::Thread(_)
            | Event::Mentioned(_)
            | Event::Bookmarks
            | Event::Reanalysed { .. } => Vec::new(),
        })
        .collect()
}

#[test]
fn a_subscriber_after_the_edits_are_checked_hears_first_those_that_do_not_resolve() {
    let path = project("unresolved-late");
    fs::write(
        path.join("project.toml"),
        "format = 1\n\n[[function]]\naddress = \"0x1\"\nname = \"gone\"\n\n\
         [[comment]]\naddress = \"0xdead0000\"\ntext = \"nowhere\"\n",
    )
    .unwrap();
    let lineage = Lineage::new(open(&path));
    let session = lineage.session();
    assert!(matches!(
        session.wait(Stage::Analysed, None),
        Waited::Reached(_)
    ));
    // Told already: a session's subscriber and a lineage's hear them as
    // they subscribe.
    let both = session.unresolved();
    assert_eq!(both.len(), 2, "{both:?}");
    assert_eq!(unresolved_told(&session.subscribe(None)), both);
    assert_eq!(unresolved_told(&lineage.subscribe(None)), both);
    // The comment written again (removed): no longer told.
    session.comment(0xdead_0000, None).unwrap();
    let left = session.unresolved();
    assert!(
        matches!(&left[..], [one] if one.edit == Edit::Function { entry: 1, name: "gone".to_owned() }),
        "{left:?}"
    );
    assert_eq!(unresolved_told(&session.subscribe(None)), left);
    assert_eq!(unresolved_told(&lineage.subscribe(None)), left);
    drop(session);
    lineage.close();
}

/// The fixture with two compilation units, its DWARF split off beside it
/// (`.gnu_debuglink`).
fn units() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/units-x86_64.elf")
}

/// Every function's document of a session on [`units`] with `debug`, and
/// the file its debug information came from.
fn units_documents(
    name: &str,
    debug: DebugSource,
) -> (BTreeMap<u64, Result<String, String>>, Option<PathBuf>) {
    let dir = project(name);
    let session = Session::open(
        units(),
        Options {
            project: Some(dir.to_path_buf()),
            debug,
            warm: false,
            identity: Some(identity()),
            ..Options::default()
        },
    )
    .unwrap();
    let events = session.subscribe(None);
    wait_for(&events, Stage::Callers);
    let database = session.database().unwrap();
    let documents = database
        .functions()
        .map(|(id, function)| {
            let text = session.document(id).map(|document| document.text.clone());
            (function.entry, text)
        })
        .collect();
    let file = session.debug_file().map(Path::to_owned);
    session.close();
    (documents, file)
}

/// A session finds the DWARF `.gnu_debuglink` names beside the binary and
/// prints as `binbun decompile --debug` does; given the file, the same;
/// told to do without, as `binbun decompile` without. Each function keeps
/// its compilation unit.
#[test]
fn debug_information_found_prints_as_the_cli_with_debug() {
    let debug = units().with_file_name("units-x86_64.debug");
    let with = as_the_cli_prints(&units(), Some(&debug));
    let without = as_the_cli_prints(&units(), None);
    assert_ne!(with, without);

    let (found, file) = units_documents("debug-found", DebugSource::Search);
    assert_eq!(found, with);
    assert_eq!(
        file.unwrap().canonicalize().unwrap(),
        debug.canonicalize().unwrap()
    );
    let (given, file) = units_documents("debug-given", DebugSource::Path(debug.clone()));
    assert_eq!(given, with);
    assert_eq!(file.unwrap(), debug);
    let (ignored, file) = units_documents("debug-ignored", DebugSource::Without);
    assert_eq!(ignored, without);
    assert!(file.is_none());

    let dir = project("debug-units");
    let session = Session::open(
        units(),
        Options {
            project: Some(dir.to_path_buf()),
            warm: false,
            identity: Some(identity()),
            ..Options::default()
        },
    )
    .unwrap();
    wait_for(&session.subscribe(None), Stage::Analysed);
    let entry = |name: &str| {
        let database = session.database().unwrap();
        database.function(function(&session, name)).unwrap().entry
    };
    let unit = |name: &str| session.source_unit(entry(name)).unwrap().path();
    assert_eq!(unit("main"), "/src/units-a.c");
    assert_eq!(unit("scale"), "/src/units-b.c");
    session.close();
}

/// The analysis fingerprint: the same for two
/// analyses of one binary with one debug file (made apart, as two
/// machines would), another without it; it names the debug file and its
/// SHA-256.
#[test]
fn the_analysis_fingerprint_is_one_per_binary_and_debug_file() {
    let debug = units().with_file_name("units-x86_64.debug");
    let print = |name: &str, source: DebugSource| {
        let dir = project(name);
        let session = Session::open(
            units(),
            Options {
                project: Some(dir.to_path_buf()),
                debug: source,
                warm: false,
                identity: Some(identity()),
                ..Options::default()
            },
        )
        .unwrap();
        wait_for(&session.subscribe(None), Stage::Analysed);
        let print = session.fingerprint().unwrap();
        session.close();
        print
    };
    let one = print("print-one", DebugSource::Path(debug.clone()));
    let two = print("print-two", DebugSource::Path(debug.clone()));
    let without = print("print-without", DebugSource::Without);
    assert_eq!(one, two);
    assert_ne!(one.analysis, without.analysis);
    assert_eq!(without.debug, None);
    let named = one.debug.unwrap();
    assert_eq!(named.name, "units-x86_64.debug");
    let digest = ring::digest::digest(&ring::digest::SHA256, &fs::read(&debug).unwrap());
    assert_eq!(named.sha256.as_slice(), digest.as_ref());
}

/// A debug file given that cannot be read is reported, and the binary
/// analysed without; reported to a subscriber that comes after the
/// failure too (as a front end subscribing once opening is under way).
#[test]
fn a_debug_file_given_that_does_not_read_is_reported() {
    let dir = project("debug-missing");
    let session = Session::open(
        units(),
        Options {
            project: Some(dir.to_path_buf()),
            debug: DebugSource::Path(units().with_file_name("no-such.debug")),
            warm: false,
            identity: Some(identity()),
            ..Options::default()
        },
    )
    .unwrap();
    session.wait(Stage::Analysed, None);
    let events = session.subscribe(None);
    let mut failed = None;
    for event in events.try_iter() {
        match event {
            Event::Failed(message) => failed = Some(message),
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
    assert!(failed.unwrap().contains("no-such.debug"));
    assert!(session.debug_file().is_none());
    assert!(session.database().unwrap().debug().is_none());
    session.close();
}

#[test]
fn questions_are_answered_as_the_engine_answers_them_and_kept() {
    let dir = project("questions");
    let session = open(&dir);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Callers);
    let id = function(&session, "loop_sum");
    let document = session.document_view(id, View::Exact).unwrap();
    let database = session.database().unwrap();

    // Verify: the engine's verdict; asked again, the kept answer at once.
    let asked = session.ask(id, View::Exact, Question::Verify(None));
    let Answer::Verified(verification) = answer_to(&events, asked.request) else {
        panic!("not a verification");
    };
    let direct = verify::verify(database, id, &verify::Options::default());
    assert_eq!(verification.verdict, direct.verdict);
    assert!(matches!(verification.verdict, Verdict::Agreed(_)));
    let again = session.ask(id, View::Exact, Question::Verify(None));
    let kept = events.try_iter().find_map(|event| {
        if let Event::Answer {
            request,
            answer: Answer::Verified(kept),
            ..
        } = event
            && request == again.request
        {
            Some(kept)
        } else {
            None
        }
    });
    assert!(Arc::ptr_eq(&kept.unwrap(), &verification), "told at once");

    // Why and origin: about the document's own L2 (the lowering they
    // start from is the one the document printed), so their variables
    // and nodes are the document's.
    let (lowered, _) = lower(database, id, View::Exact, &[]).unwrap();
    assert_eq!(lowered.l2, document.decompiled.l2);
    let var = a_variable(&document);
    let asked = session.ask(id, View::Exact, Question::Explain);
    let Answer::Explained(Ok(explanation)) = answer_to(&events, asked.request) else {
        panic!("no explanation");
    };
    assert!(explanation.items.iter().any(|item| item.var == Some(var)));
    let asked = session.ask(id, View::Exact, Question::Origins(Start::Var(var)));
    let Answer::Origins(Ok(answered)) = answer_to(&events, asked.request) else {
        panic!("no origins");
    };
    let direct = origins(database, id, Start::Var(var), &Query::default()).unwrap();
    assert_eq!(*answered, direct);
    let printed: Vec<Node> = document.spans.iter().filter_map(|span| span.node).collect();

    // Run: the engine's run of the document's own L2, its statements
    // the printed ones; kept by its state.
    let state = Arc::new(ExampleState::scratch("scratch"));
    let asked = session.ask(id, View::Exact, Question::Run(Arc::clone(&state), None));
    let Answer::Ran(Ok(ran)) = answer_to(&events, asked.request) else {
        panic!("no run");
    };
    let never = AtomicBool::new(false);
    let direct = run::run_decompiled(
        database,
        &document.decompiled,
        &state,
        &run::Options::default(),
        &never,
    )
    .unwrap();
    assert_eq!(*ran, direct);
    assert!(
        ran.c
            .statements
            .keys()
            .all(|stmt| printed.contains(&Node::Stmt(*stmt)))
    );
    let kept = Question::Run(Arc::new(ExampleState::scratch("scratch")), None);
    let other = Question::Run(Arc::new(ExampleState::scratch("other")), None);
    // A run on a processor is another question than the architecture's.
    let on = Question::Run(
        Arc::new(ExampleState::scratch("scratch")),
        binbun::profile::embedded().first().cloned(),
    );
    assert!(
        matches!(session.answer(id, View::Exact, &kept), Some(Answer::Ran(Ok(r))) if Arc::ptr_eq(&r, &ran))
    );
    assert!(session.answer(id, View::Exact, &other).is_none());
    assert!(session.answer(id, View::Exact, &on).is_none());

    // Stages: the engine's, kept per view.
    let asked = session.ask(id, View::Reading, Question::Stages);
    let Answer::Staged(Ok(staged)) = answer_to(&events, asked.request) else {
        panic!("no stages");
    };
    let reading = stages::Options {
        view: View::Reading,
        ..stages::Options::default()
    };
    assert_eq!(*staged, stages(database, id, &reading).unwrap());
    assert!(
        matches!(session.answer(id, View::Reading, &Question::Stages), Some(Answer::Staged(Ok(s))) if Arc::ptr_eq(&s, &staged))
    );
    assert!(session.answer(id, View::Exact, &Question::Stages).is_none());
    session.close();
}

#[test]
fn call_sites_print_their_callers_lines_with_the_users_names() {
    let dir = project("calls");
    let session = open(&dir);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Callers);
    let classify = function(&session, "classify");
    let checked = function(&session, "checked");
    let sites = |id: FunctionId, question: Question| {
        let asked = session.ask(id, View::Exact, question);
        let Answer::Calls(sites) = answer_to(&events, asked.request) else {
            panic!("no call sites");
        };
        sites
    };

    // `classify`'s one caller, `checked`, with its C line.
    let callers = sites(classify, Question::Callers);
    assert_eq!(callers.len(), 1);
    assert_eq!(callers[0].call.caller, checked);
    assert_eq!(callers[0].line.as_deref(), Some("return classify(a1) * 2;"));
    // `checked`'s calls: `fail` with the string's address.
    let calls = sites(checked, Question::Callees);
    let fail = calls
        .iter()
        .find(|site| site.line.as_deref() == Some("fail(\"negative\");"))
        .unwrap();
    assert!(matches!(fail.arguments[..], [Known::Constant(_)]));

    // Renamed, the line prints the new name: call sites are not kept.
    let entry = session
        .database()
        .unwrap()
        .function(classify)
        .unwrap()
        .entry;
    session.rename_function(entry, Some("kind")).unwrap();
    let callers = sites(classify, Question::Callers);
    assert_eq!(callers[0].line.as_deref(), Some("return kind(a1) * 2;"));

    // Paths, by calls and by data, and kept.
    let main = function(&session, "main");
    let query = PathQuery {
        from: Some(Callee::Function(main)),
        to: Some(Callee::Function(classify)),
        limit: 4,
        ..PathQuery::default()
    };
    let by_calls = Question::Paths(Arc::new(PathRequest {
        query: query.clone(),
        data: None,
    }));
    let asked = session.ask(main, View::Exact, by_calls.clone());
    let Answer::Paths(found) = answer_to(&events, asked.request) else {
        panic!("no paths");
    };
    assert_eq!(found.shortest, Some(3));
    assert!(session.answer(main, View::Exact, &by_calls).is_some());
    let by_data = Question::Paths(Arc::new(PathRequest {
        query,
        data: Some(0),
    }));
    let asked = session.ask(main, View::Exact, by_data);
    let Answer::Paths(found) = answer_to(&events, asked.request) else {
        panic!("no paths");
    };
    // `argc` stops at `loop_sum`'s loop bound.
    assert_eq!(found.shortest, None);
    session.close();
}

#[test]
fn cancelling_stops_the_worker() {
    let dir = project("cancel");
    let session = open(&dir);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (cancelled, at) = mpsc::channel();
    {
        let seen = Arc::clone(&seen);
        let cancel = session.canceller();
        // Cancelled on the worker's thread as the warming starts: no
        // function is warmed. (Registered once it began, as the worker may
        // be that quick, told the stage reached first: cancelled then.)
        session.on_event(move |event| {
            let mut seen = seen.lock().unwrap();
            let warming = matches!(event, Event::Progress { .. })
                || (seen.is_empty() && matches!(event, Event::Stage(s) if *s >= Stage::Callers));
            if warming {
                cancel.cancel();
                let _ = cancelled.send(seen.len());
            }
            seen.push(event.clone());
        });
    }
    let at: usize = at.recv_timeout(Duration::from_secs(120)).unwrap();
    // The worker stopped: a request finds no one to answer it.
    let (any, _) = session.database().unwrap().functions().next().unwrap();
    assert!(session.document(any).is_err());
    session.close();
    let seen = seen.lock().unwrap();
    assert!(
        !seen[at + 1..]
            .iter()
            .any(|event| matches!(event, Event::Stage(Stage::Warmed))),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|event| matches!(event, Event::Stage(stage) if *stage >= Stage::Callers)),
        "{seen:?}"
    );
}

#[test]
fn a_frame_slot_is_its_one_variable_else_named_as_a_slot_and_saved() {
    let path = project("slots");
    let session = open(&path);
    let events = session.subscribe(None);
    wait_for(&events, Stage::Analysed);
    // Every variable the C prints that alone is one slot is that slot's
    // variable.
    let mut found = 0;
    let ids: Vec<FunctionId> = session
        .database()
        .unwrap()
        .functions()
        .map(|(id, _)| id)
        .collect();
    for id in ids {
        let Ok(document) = session.document(id) else {
            continue;
        };
        let l2 = &document.decompiled.l2;
        let printed = |var: VarId| {
            document
                .spans
                .iter()
                .any(|span| span.node == Some(Node::Var(var)))
        };
        let slots: Vec<(VarId, i64)> = (0..l2.variables.len())
            .filter_map(|var| {
                let var = VarId(u32::try_from(var).unwrap());
                if !printed(var) {
                    return None;
                }
                let slot = session.variable(id, View::Exact, var).ok()?.slot()?;
                Some((var, slot))
            })
            .collect();
        for &(var, slot) in &slots {
            let alone = slots.iter().filter(|&&(_, s)| s == slot).count() == 1;
            let shared = l2.variables.iter().enumerate().any(|(other, v)| {
                let other_var = VarId(u32::try_from(other).unwrap());
                other != var.0 as usize
                    && printed(other_var)
                    && v.origins.contains(&Origin::Slot(slot))
            });
            if alone && !shared {
                assert_eq!(session.slot_variable(id, slot).unwrap(), Some(var));
                found += 1;
            }
        }
    }
    assert!(found > 0, "no variable is one frame slot");
    // A slot no variable is: named as a slot, its function's code
    // listed as changed, saved.
    let sum = function(&session, "loop_sum");
    let entry = session.database().unwrap().function(sum).unwrap().entry;
    assert_eq!(session.slot_variable(sum, -0x1000).unwrap(), None);
    let change = session.rename_slot(entry, -0x1000, Some("spill")).unwrap();
    assert!(change.listing.iter().any(|range| range.contains(&entry)));
    assert_eq!(session.edits().slot(entry, -0x1000), Some("spill"));
    session.save().unwrap();
    session.close();
    let saved = fs::read_to_string(path.join("project.toml")).unwrap();
    assert!(saved.contains("[[slot]]"), "{saved}");
    let session = open(&path);
    // The project's edits are loaded once the image is parsed.
    wait_for(&session.subscribe(None), Stage::Image);
    assert_eq!(session.edits().slot(entry, -0x1000), Some("spill"));
    session.rename_slot(entry, -0x1000, None).unwrap();
    assert_eq!(session.edits().slot(entry, -0x1000), None);
    session.close();
}
