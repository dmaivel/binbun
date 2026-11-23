#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! Debug information from a symbol server in a session, with a local
//! server standing in for debuginfod (no test touches the network):
//! asked for, nothing is sent until the front end answers; always, it is
//! fetched while the analysis goes on and the C opened with it takes its
//! names; never, nothing is sent; once cached, it is used without asking.

mod common;
#[path = "../../binbun-debuginfo/tests/support/server.rs"]
mod server;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use binbun_debuginfo::symbols::{Config, Identity, Server};
use binbun_session::{DebugSource, Download, Event, Options, Session, Stage, SymbolState, Symbols};
use common::Scratch;
use server::LocalServer;

/// The fixture with two compilation units, whose DWARF is split off.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// A fresh directory for test `name` holding the binary alone (its debug
/// file is not beside it), the binary, and a symbol cache.
fn scratch(name: &str) -> (Scratch, PathBuf, PathBuf) {
    let dir = Scratch::new(&format!("session-symbols-{name}"));
    let binary = dir.join("units-x86_64.elf");
    fs::copy(fixture("units-x86_64.elf"), &binary).unwrap();
    let cache = dir.join("cache");
    (dir, binary, cache)
}

/// The server holding the binary's debug file at debuginfod's path.
fn debuginfod() -> LocalServer {
    let identity = Identity::of(&fs::read(fixture("units-x86_64.elf")).unwrap()).unwrap();
    let (url, _) = identity.urls("").remove(0);
    LocalServer::serve(vec![(
        url,
        fs::read(fixture("units-x86_64.debug")).unwrap(),
    )])
}

/// Options for `binary`, fetching under `download` from `server` into
/// `cache`, no warming.
fn options(binary: &Path, download: Download, server: &LocalServer, cache: &Path) -> Options {
    let mut project = binary.as_os_str().to_owned();
    project.push(".project");
    Options {
        project: Some(PathBuf::from(project)),
        warm: false,
        symbols: Symbols {
            download,
            config: Config {
                stores: vec![cache.to_owned()],
                pdb_servers: Vec::new(),
                debuginfod: vec![Server::new(&server.url, cache)],
                timeout: Duration::from_secs(5),
            },
        },
        identity: Some(identity()),
        ..Options::default()
    }
}

/// The identity these tests sign their changes with: never the user's.
fn identity() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("identity")
}

/// The `Event::Symbols` states told until `stage` is reached, and until
/// `until` holds of one if given.
fn told(
    events: &Receiver<Event>,
    stage: Stage,
    until: Option<fn(&SymbolState) -> bool>,
) -> Vec<SymbolState> {
    told_from(events, Some(stage), until)
}

/// The `Event::Symbols` states told until a fetch ends (the stages
/// already reached).
fn settled(events: &Receiver<Event>) -> Vec<SymbolState> {
    told_from(events, None, Some(fetched))
}

/// [`told`], waiting for no stage if `wanted` is `None`.
fn told_from(
    events: &Receiver<Event>,
    wanted: Option<Stage>,
    until: Option<fn(&SymbolState) -> bool>,
) -> Vec<SymbolState> {
    let mut states = Vec::new();
    let mut reached = wanted.is_none();
    let mut done = until.is_none();
    while !(reached && done) {
        match events.recv_timeout(Duration::from_secs(120)).unwrap() {
            Event::Stage(at) if wanted.is_some_and(|wanted| at >= wanted) => reached = true,
            Event::Symbols(state) => {
                done |= until.is_some_and(|ends| ends(&state));
                states.push(state);
            }
            Event::Failed(message) => panic!("{message}"),
            Event::Stage(_)
            | Event::Progress { .. }
            | Event::Changed(_)
            | Event::Document { .. }
            | Event::Unresolved(_)
            | Event::Answer { .. }
            | Event::History(_)
            | Event::Conflicts(_)
            | Event::Thread(_)
            | Event::Mentioned(_)
            | Event::Bookmarks
            | Event::Reanalysed { .. } => {}
        }
    }
    states
}

fn fetched(state: &SymbolState) -> bool {
    matches!(
        state,
        SymbolState::Fetched { .. } | SymbolState::Failed { .. }
    )
}

/// Every function's C in `session`, by entry.
fn documents(session: &Session) -> BTreeMap<u64, Result<String, String>> {
    let database = session.database().unwrap();
    database
        .functions()
        .map(|(id, function)| {
            let text = session.document(id).map(|document| document.text.clone());
            (function.entry, text)
        })
        .collect()
}

/// The C of the fixture with its debug file given.
fn with_debug(binary: &Path) -> BTreeMap<u64, Result<String, String>> {
    let mut project = binary.as_os_str().to_owned();
    project.push(".given.project");
    let session = Session::open(
        binary,
        Options {
            project: Some(PathBuf::from(project)),
            warm: false,
            debug: DebugSource::Path(fixture("units-x86_64.debug")),
            identity: Some(identity()),
            ..Options::default()
        },
    )
    .unwrap();
    told(&session.subscribe(None), Stage::Callers, None);
    documents(&session)
}

#[test]
fn asked_nothing_is_sent_until_answered_then_the_c_takes_the_debug_information() {
    let (_dir, binary, cache) = scratch("ask");
    let server = debuginfod();
    let host = server.url.trim_start_matches("http://").to_owned();
    let session = Session::open(&binary, options(&binary, Download::Ask, &server, &cache)).unwrap();
    let events = session.subscribe(None);
    let offered = SymbolState::Available {
        binary: "units-x86_64.elf".to_owned(),
        server: host.clone(),
    };
    assert_eq!(
        told(&events, Stage::Callers, None),
        std::slice::from_ref(&offered)
    );
    assert_eq!(session.symbols(), Some(offered));
    assert_eq!(server.requests(), Vec::<String>::new());
    assert!(session.debug_file().is_none());
    let without = documents(&session);

    assert!(session.fetch_symbols());
    let states = settled(&events);
    let [
        SymbolState::Fetching { .. },
        SymbolState::Fetched {
            path, server: from, ..
        },
    ] = &states[..]
    else {
        panic!("{states:?}");
    };
    assert_eq!(from, &host);
    assert_eq!(server.requests().len(), 1);
    assert!(!session.fetch_symbols(), "fetched once");

    // Decompiled again with it: the C changes, as given the debug file.
    let again = session.with_debug(path).unwrap();
    told(&again.subscribe(None), Stage::Callers, None);
    assert_eq!(again.debug_file(), Some(path.as_path()));
    let debugged = documents(&again);
    assert_ne!(debugged, without);
    assert_eq!(debugged, with_debug(&binary));
    assert_eq!(again.symbols(), None);
    again.close();
    session.close();

    // Opened again: the cache has it, nothing asked or sent.
    let reopened =
        Session::open(&binary, options(&binary, Download::Ask, &server, &cache)).unwrap();
    assert_eq!(
        told(&reopened.subscribe(None), Stage::Callers, None),
        Vec::new()
    );
    assert_eq!(reopened.debug_file(), Some(path.as_path()));
    assert_eq!(server.requests().len(), 1);
    reopened.close();
}

#[test]
fn always_fetches_while_the_analysis_goes_on() {
    let (_dir, binary, cache) = scratch("always");
    let server = debuginfod();
    let session =
        Session::open(&binary, options(&binary, Download::Always, &server, &cache)).unwrap();
    let states = told(&session.subscribe(None), Stage::Callers, Some(fetched));
    // The fetch starts on the worker as soon as the image is parsed, which
    // may be before this subscribes: a subscriber is told the state
    // reached, then each one after, so it hears the steps from where the
    // fetch was, in order.
    let Some(SymbolState::Fetched { path, .. }) = states.last() else {
        panic!("{states:?}");
    };
    let steps: [fn(&SymbolState) -> bool; 3] = [
        |s: &SymbolState| matches!(s, SymbolState::Available { .. }),
        |s: &SymbolState| matches!(s, SymbolState::Fetching { .. }),
        |s: &SymbolState| matches!(s, SymbolState::Fetched { .. }),
    ];
    let from = steps.len() - states.len().min(steps.len());
    assert!(
        states.len() <= steps.len() && states.iter().zip(&steps[from..]).all(|(s, is)| is(s)),
        "{states:?}"
    );
    assert_eq!(server.requests().len(), 1);
    let again = session.with_debug(path).unwrap();
    told(&again.subscribe(None), Stage::Callers, None);
    assert_eq!(documents(&again), with_debug(&binary));
    again.close();
    session.close();
}

#[test]
fn never_sends_anything() {
    let (_dir, binary, cache) = scratch("never");
    let server = debuginfod();
    let session =
        Session::open(&binary, options(&binary, Download::Never, &server, &cache)).unwrap();
    assert_eq!(
        told(&session.subscribe(None), Stage::Callers, None),
        Vec::new()
    );
    assert_eq!(session.symbols(), None);
    assert!(!session.fetch_symbols());
    assert_eq!(server.requests(), Vec::<String>::new());
    session.close();
}

#[test]
fn a_failed_fetch_says_why_and_may_be_tried_again() {
    let (_dir, binary, cache) = scratch("failed");
    let empty = LocalServer::serve(Vec::new());
    let session =
        Session::open(&binary, options(&binary, Download::Always, &empty, &cache)).unwrap();
    let events = session.subscribe(None);
    let states = told(&events, Stage::Callers, Some(fetched));
    let host = empty.url.trim_start_matches("http://");
    assert_eq!(
        states.last(),
        Some(&SymbolState::Failed {
            binary: "units-x86_64.elf".to_owned(),
            reason: format!("not found on {host}"),
        })
    );
    assert!(session.fetch_symbols());
    let again = settled(&events);
    assert!(matches!(
        &again[..],
        [SymbolState::Fetching { .. }, SymbolState::Failed { .. }]
    ));
    assert_eq!(empty.requests().len(), 2);
    session.close();
}
