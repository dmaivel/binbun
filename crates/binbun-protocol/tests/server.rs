//! Servers of one process: each keeps its own socket and discovery file,
//! so stopping one never takes another's away (nor waits forever for a
//! listener it can no longer wake), and one stopped as soon as it started
//! stops. Connections at once, each answered,
//! and one closed ending its transaction: on a Unix socket, and on
//! Windows over a named pipe.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use binbun_protocol::FaultKind;
use binbun_protocol::client::Client;
use binbun_protocol::discovery;
use binbun_protocol::handshake::{Initialize, PROTOCOL_VERSION};
use binbun_protocol::messages::{Apply, Begin, Note, method};
use binbun_protocol::server::Server;
use binbun_protocol::{Host, Write};
use binbun_session::{Lineage, Options, Stage};

fn initialize(database: Option<u64>) -> Initialize {
    Initialize {
        client: "test".to_owned(),
        protocol: [1, PROTOCOL_VERSION],
        api: [0, 3],
        database,
        author: None,
        agent: None,
    }
}

/// A fresh directory of this test's, `binbun` in it for the servers.
fn scratch(name: &str) -> PathBuf {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// Whether the server at `socket` answers: it has no database, so the
/// handshake is refused as ambiguous, by the server.
fn answers(socket: &Path) -> bool {
    matches!(
        Client::connect(socket, &initialize(None)),
        Err(fault) if fault.kind == FaultKind::Ambiguous
    )
}

#[test]
fn two_servers_of_one_process_keep_apart_and_each_stops_alone() {
    let dir = scratch("two-servers").join("binbun");
    let first = Server::start(&dir, "test/1").unwrap();
    let second = Server::start(&dir, "test/2").unwrap();
    assert_ne!(first.socket(), second.socket());
    assert_eq!(discovery::servers(&dir).unwrap().len(), 2);
    assert!(answers(first.socket()) && answers(second.socket()));

    let first_socket = first.socket().to_owned();
    drop(second);
    // The first still answers, and is still found.
    assert!(answers(&first_socket));
    let found = discovery::servers(&dir).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].socket, first_socket);

    // Its socket removed by hand: stopping it returns all the same. (A
    // pipe cannot be: it goes with its server.)
    #[cfg(unix)]
    fs::remove_file(&first_socket).unwrap();
    drop(first);
    assert_eq!(discovery::servers(&dir).unwrap(), Vec::new());
    // Stopped, it is not reached.
    let fault = Client::connect(&first_socket, &initialize(None)).unwrap_err();
    assert_eq!(fault.kind, FaultKind::Connection, "{}", fault.message);
}

/// A server stopped at once, its listener perhaps not yet waiting for a
/// client: stopping wakes it all the same (a named pipe's client gone
/// before the listener waits is never seen, so the waking one stays
/// connected until the listener has ended), many times over.
#[test]
fn a_server_stopped_as_soon_as_it_starts_stops() {
    let dir = scratch("stopped-at-once").join("binbun");
    let (done, stopped) = mpsc::channel();
    thread::spawn(move || {
        for n in 0..200 {
            drop(Server::start(&dir, &format!("test/{n}")).unwrap());
        }
        done.send(()).unwrap();
    });
    stopped
        .recv_timeout(Duration::from_secs(120))
        .expect("a server's stop waits forever for its listener");
}

/// Clients connect at once and are each answered; one closes with a
/// transaction open, and the server, reading the end of its connection,
/// rolls it back: the other's transaction may begin, and the comment
/// written in it is gone.
#[test]
fn clients_at_once_are_answered_and_a_closed_ones_transaction_is_rolled_back() {
    let dir = scratch("round-trip");
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf");
    let lineage = Arc::new(
        Lineage::open(
            &fixture,
            Options {
                project: Some(dir.join("project")),
                identity: Some(dir.join("identity")),
                warm: false,
                ..Options::default()
            },
        )
        .unwrap(),
    );
    lineage.session().wait(Stage::Callers, None);
    let server = Server::start(&dir.join("binbun"), "test/round-trip").unwrap();
    let id = server
        .add(&fixture, Arc::new(Host::new(lineage, false)), None)
        .unwrap();

    let clients: Vec<Client> = thread::scope(|scope| {
        let connecting: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    let client = Client::connect(server.socket(), &initialize(Some(id))).unwrap();
                    let comments: Vec<Note> = client.call(method::COMMENTS, ()).unwrap();
                    assert_eq!(comments, Vec::new());
                    client
                })
            })
            .collect();
        connecting
            .into_iter()
            .map(|connecting| connecting.join().unwrap())
            .collect()
    });
    let [leaving, staying, ..] = clients.as_slice() else {
        unreachable!("four clients")
    };

    let begin = Begin {
        label: "left open".to_owned(),
        author: None,
    };
    let () = leaving.call(method::BEGIN, &begin).unwrap();
    let comment = Apply {
        write: Write::Comment {
            address: 0x1194,
            text: Some("left open".to_owned()),
        },
    };
    let _: serde_json::Value = leaving.call(method::APPLY, &comment).unwrap();
    let refused = staying.call::<()>(method::BEGIN, &begin).unwrap_err();
    assert_eq!(refused.kind, FaultKind::Transaction, "{}", refused.message);

    leaving.close();
    let deadline = Instant::now() + Duration::from_secs(20);
    while staying.call::<()>(method::BEGIN, &begin).is_err() {
        assert!(
            Instant::now() < deadline,
            "the closed client's transaction stays open"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let comments: Vec<Note> = staying.call(method::COMMENTS, ()).unwrap();
    assert_eq!(comments, Vec::new());
    let () = staying.call(method::ROLLBACK, ()).unwrap();
    // The closed client knows it is.
    assert_eq!(
        leaving.call::<()>(method::ROLLBACK, ()).unwrap_err().kind,
        FaultKind::Connection
    );
}
