//! The server: a Unix socket (0600) in the user's own directory (0700,
//! [`discovery`]) beside its discovery
//! file (on Windows a named pipe its owner's alone, named in the discovery
//! file), answering each connection on a thread of its own. A connection
//! attaches to one of the databases served ([`Server::add`]) and writes
//! through its [`Host`] as an owner of its own: its transactions are its
//! own, and one left open when it goes is rolled back. Framework-free:
//! the GUI serves its windows' binaries, a script its own
//! (`Database.serve()`).

use std::collections::BTreeMap;
use std::fmt;
#[cfg(unix)]
use std::fs;
use std::io::{BufReader, BufWriter};
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use binbun::Database as Engine;
use binbun::cfg::FunctionId;
use binbun_session::journal::{Origin, PublicKey};
use binbun_session::{Event, Key, Session};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::base64;
use crate::discovery::{self, Discovery};
use crate::fault::{Fault, FaultKind};
use crate::framing::{read_frame, write_frame};
use crate::handshake::{DatabaseInfo, Initialize, Initialized, capability, negotiate};
use crate::host::{Host, Owner};
use crate::messages::{
    Apply, At, Begin, ChangedNote, Changes, ChangesSince, CommitResult, Cursor, Entries,
    FunctionInfo, FunctionPage, HistoryNote, ListFunctions, Member, Note, Presence, ReanalysedNote,
    Settle, Span, StageNote, Subscribe, Text, method, notification,
};
use crate::rpc::{INVALID_REQUEST, METHOD_NOT_FOUND, Message, RpcError};
use crate::socket::{Listener, Stream};
use crate::sync;
use crate::talk::{self, MentionedNote, ThreadNote};
use crate::types::{HistoryItem, RevisionData, stage_number};

/// The GUI's side of `ui.cursor` and `ui.selection`: read from the
/// server's threads, so the GUI keeps it as plain data.
pub trait Ui: Send + Sync {
    /// Where the cursor is, if a pane shows the binary.
    fn cursor(&self) -> Option<u64>;
    /// Moves the cursor to `address` (the GUI does it on its own thread).
    fn goto(&self, address: u64);
    /// The selection, if one is made.
    fn selection(&self) -> Option<(u64, u64)>;
    /// Agent connection `connection` came (`Some`) or went (`None`): the
    /// window shows it among the participants while it is connected.
    fn agent(&self, connection: u64, agent: Option<ConnectedAgent>);
    /// Agent connection `connection`'s code works at `address` (its
    /// cursor, as a collaborator's).
    fn agent_at(&self, connection: u64, address: Option<u64>);
    /// The people of the session as the window knows them: its user
    /// (`you`) and, in a shared session, the members (agents among them
    /// with their roles).
    fn people(&self) -> Vec<Member>;
}

/// An agent connected ([`Initialize::agent`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectedAgent {
    /// Its identity key, held by the server's install.
    pub key: PublicKey,
    /// Its name (`Codex`).
    pub name: String,
    /// Its version, if it said.
    pub version: Option<String>,
}

/// A database served: its host, its file, the GUI's side if it has one.
#[derive(Clone)]
struct Served {
    host: Arc<Host>,
    path: PathBuf,
    ui: Option<Arc<dyn Ui>>,
    /// When its window last had the focus (Unix milliseconds).
    focused: Option<u64>,
}

impl fmt::Debug for Served {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Served")
            .field("path", &self.path)
            .field("ui", &self.ui.is_some())
            .finish_non_exhaustive()
    }
}

/// What the server's threads share.
#[derive(Debug)]
struct Shared {
    /// The server's name and version (`binbun-gui/0.0.0`).
    name: String,
    dir: PathBuf,
    socket: PathBuf,
    /// The name its socket and discovery file share ([`discovery::stem`]).
    stem: String,
    pid: u32,
    databases: Mutex<BTreeMap<u64, Served>>,
    next_database: AtomicU64,
    next_owner: AtomicU64,
    stopped: AtomicBool,
    /// The agent connections: their database and key, by connection.
    agents: Mutex<BTreeMap<Owner, (u64, PublicKey)>>,
}

impl Shared {
    fn databases(&self) -> MutexGuard<'_, BTreeMap<u64, Served>> {
        self.databases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn served(&self, id: u64) -> Option<Served> {
        self.databases().get(&id).cloned()
    }

    fn agents(&self) -> MutexGuard<'_, BTreeMap<Owner, (u64, PublicKey)>> {
        self.agents.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every database served, as told.
    fn infos(&self) -> Vec<DatabaseInfo> {
        self.databases()
            .iter()
            .map(|(&id, served)| info(id, served))
            .collect()
    }

    /// Writes the discovery file again (the databases served changed).
    fn publish(&self) -> Result<(), Fault> {
        discovery::publish(
            &self.dir,
            &self.stem,
            &Discovery {
                pid: self.pid,
                server: self.name.clone(),
                socket: self.socket.clone(),
                databases: self.infos(),
            },
        )
    }
}

/// `served` (number `id`) as told.
fn info(id: u64, served: &Served) -> DatabaseInfo {
    let session = served.host.lineage().session();
    DatabaseInfo {
        id,
        path: served.path.display().to_string(),
        name: served
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        sha256: session.key().map(Key::hex),
        debug: session.debug_file().map(|path| path.display().to_string()),
        arch: session.slice().map(str::to_owned),
        stage: stage_number(session.stage()),
        revision: RevisionData::from(session.revision()),
        focused: served.focused,
    }
}

/// The first owner number a connection gets (below: a process's own
/// threads, and the GUI's user).
const CONNECTIONS: Owner = 1 << 62;

/// How many servers this process started: each names its files apart.
static STARTED: AtomicU64 = AtomicU64::new(0);

/// A server listening on its socket until dropped.
#[derive(Debug)]
pub struct Server {
    shared: Arc<Shared>,
    listening: Option<thread::JoinHandle<()>>,
}

impl Server {
    /// Listens on `<dir>/gui-<pid>[-<n>].sock` (0600; `dir` made 0700;
    /// [`discovery::stem`]; on Windows the pipe [`discovery::pipe`]) as
    /// `name` (`binbun-gui/0.0.0`), its discovery file in `dir`.
    ///
    /// # Errors
    ///
    /// `dir` is open to others or cannot be made; the socket cannot be
    /// bound; the discovery file cannot be written.
    pub fn start(dir: &Path, name: &str) -> Result<Self, Fault> {
        discovery::make_private(dir)?;
        let pid = std::process::id();
        let stem = discovery::stem(pid, STARTED.fetch_add(1, Ordering::Relaxed));
        #[cfg(unix)]
        let socket = {
            let socket = discovery::socket(dir, &stem);
            let _ = fs::remove_file(&socket);
            socket
        };
        #[cfg(windows)]
        let socket = discovery::pipe(
            &stem,
            getrandom::u64().map_err(|error| Fault::new(FaultKind::Binbun, error.to_string()))?,
        );
        let listener = Listener::bind(&socket).map_err(|error| {
            Fault::new(
                FaultKind::Connection,
                format!("{}: {error}", socket.display()),
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).map_err(|error| {
                Fault::new(
                    FaultKind::Connection,
                    format!("{}: {error}", socket.display()),
                )
            })?;
        }
        let shared = Arc::new(Shared {
            name: name.to_owned(),
            dir: dir.to_owned(),
            socket,
            stem,
            pid,
            databases: Mutex::new(BTreeMap::new()),
            next_database: AtomicU64::new(1),
            next_owner: AtomicU64::new(CONNECTIONS),
            stopped: AtomicBool::new(false),
            agents: Mutex::new(BTreeMap::new()),
        });
        shared.publish()?;
        let listening = {
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("binbun-server".to_owned())
                .spawn(move || listen(&shared, &listener))
                .map_err(|error| Fault::new(FaultKind::Binbun, error.to_string()))?
        };
        Ok(Self {
            shared,
            listening: Some(listening),
        })
    }

    /// Its socket.
    pub fn socket(&self) -> &Path {
        &self.shared.socket
    }

    /// Serves `host` (the binary at `path`), with the GUI's cursor and
    /// selection if `ui`; its number.
    ///
    /// # Errors
    ///
    /// The discovery file cannot be written.
    pub fn add(&self, path: &Path, host: Arc<Host>, ui: Option<Arc<dyn Ui>>) -> Result<u64, Fault> {
        let id = self.shared.next_database.fetch_add(1, Ordering::Relaxed);
        self.shared.databases().insert(
            id,
            Served {
                host,
                path: path.to_owned(),
                ui,
                focused: None,
            },
        );
        self.shared.publish()?;
        Ok(id)
    }

    /// Database `id`'s window has the focus (now): a client naming no
    /// database attaches to the one focused last.
    ///
    /// # Errors
    ///
    /// The discovery file cannot be written.
    pub fn focus(&self, id: u64) -> Result<(), Fault> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        match self.shared.databases().get_mut(&id) {
            Some(served) => served.focused = Some(now),
            None => return Ok(()),
        }
        self.shared.publish()
    }

    /// Serves database `id` no more (its connections' requests fail).
    ///
    /// # Errors
    ///
    /// The discovery file cannot be written.
    pub fn remove(&self, id: u64) -> Result<(), Fault> {
        self.shared.databases().remove(&id);
        self.shared.publish()
    }

    /// Writes the discovery file again: a database's stage or revision
    /// moved.
    ///
    /// # Errors
    ///
    /// It cannot be written.
    pub fn publish(&self) -> Result<(), Fault> {
        self.shared.publish()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shared.stopped.store(true, Ordering::Relaxed);
        // Wakes the listener so that it sees it is stopped. If its socket
        // is gone (removed by hand) nothing can wake it: it is left
        // blocked rather than waited for forever. The waking connection
        // stays open until the listener has ended: a named pipe's client
        // gone before the listener waits on its instance is never seen
        // (interprocess's accept takes it for dead and waits for the
        // next), which would leave the listener blocked.
        let woke = Stream::connect(&self.shared.socket);
        if let Some(listening) = self.listening.take()
            && woke.is_ok()
        {
            let _ = listening.join();
        }
        drop(woke);
        discovery::withdraw(&self.shared.dir, &self.shared.stem);
    }
}

/// Accepts connections until stopped, each answered on a thread.
fn listen(shared: &Arc<Shared>, listener: &Listener) {
    for stream in listener.incoming() {
        if shared.stopped.load(Ordering::Relaxed) {
            break;
        }
        let Ok(stream) = stream else { continue };
        let shared = Arc::clone(shared);
        let owner = shared.next_owner.fetch_add(1, Ordering::Relaxed);
        let _ = thread::Builder::new()
            .name(format!("binbun-connection-{}", owner - CONNECTIONS))
            .spawn(move || serve(&shared, &stream, owner));
    }
}

/// What one connection says to its client: responses and notifications,
/// each written whole.
type Writer = Arc<Mutex<BufWriter<Stream>>>;

/// Writes `message` to `writer`; whether it could.
fn send(writer: &Writer, message: &Message) -> bool {
    let Ok(bytes) = message.to_bytes() else {
        return false;
    };
    let mut writer = writer.lock().unwrap_or_else(PoisonError::into_inner);
    write_frame(&mut *writer, &bytes).is_ok()
}

/// One connection's state.
struct Connection {
    shared: Arc<Shared>,
    owner: Owner,
    writer: Writer,
    /// The database attached at `initialize`.
    database: Option<u64>,
    /// Who makes its writes made outside a transaction.
    origin: Origin,
    /// The agent it is, if one: its writes are signed by its key.
    agent: Option<ConnectedAgent>,
    /// Set when the connection ends: its notifications stop.
    closed: Arc<AtomicBool>,
    subscribed: bool,
}

/// Answers one connection until it ends, then rolls back the transaction
/// it left open.
fn serve(shared: &Arc<Shared>, stream: &Stream, owner: Owner) {
    let (Ok(reading), Ok(writing)) = (stream.try_clone(), stream.try_clone()) else {
        return;
    };
    let mut connection = Connection {
        shared: Arc::clone(shared),
        owner,
        writer: Arc::new(Mutex::new(BufWriter::new(writing))),
        database: None,
        origin: Origin::Script("python".to_owned()),
        agent: None,
        closed: Arc::new(AtomicBool::new(false)),
        subscribed: false,
    };
    let mut reader = BufReader::new(reading);
    while let Ok(Some(bytes)) = read_frame(&mut reader) {
        if shared.stopped.load(Ordering::Relaxed) {
            break;
        }
        let message = match Message::from_bytes(&bytes) {
            Ok(message) => message,
            Err(error) => {
                if !send(&connection.writer, &Message::response(None, Err(error))) {
                    break;
                }
                continue;
            }
        };
        let Some(method) = message.method.as_deref() else {
            continue;
        };
        let outcome = connection.answer(method, message.params.unwrap_or(Value::Null));
        // A notification from the client is answered by nothing.
        if let Some(id) = message.id
            && !send(&connection.writer, &Message::response(Some(id), outcome))
        {
            break;
        }
    }
    connection.closed.store(true, Ordering::Relaxed);
    if let Some(served) = connection.database.and_then(|id| shared.served(id)) {
        served.host.abandon(owner);
        if connection.agent.is_some() {
            shared.agents().remove(&owner);
            if let Some(ui) = &served.ui {
                ui.agent(owner, None);
            }
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

/// `params` as a method's parameters.
fn params<T: DeserializeOwned>(params: Value) -> Result<T, RpcError> {
    serde_json::from_value(params).map_err(|error| {
        RpcError::fault(Fault::new(
            FaultKind::Protocol,
            format!("bad parameters: {error}"),
        ))
    })
}

/// `value` as a result.
fn result<T: Serialize>(value: &T) -> Result<Value, RpcError> {
    serde_json::to_value(value)
        .map_err(|error| RpcError::fault(Fault::new(FaultKind::Protocol, error.to_string())))
}

/// No method `method`.
fn no_method(method: &str) -> RpcError {
    RpcError {
        code: METHOD_NOT_FOUND,
        message: format!("no method {method:?}"),
        data: Some(Fault::new(
            FaultKind::Protocol,
            format!("no method {method:?}"),
        )),
    }
}

impl Connection {
    /// The database attached.
    fn served(&self) -> Result<Served, RpcError> {
        let id = self.database.ok_or_else(|| RpcError {
            code: INVALID_REQUEST,
            message: "initialize first".to_owned(),
            data: Some(Fault::new(FaultKind::Protocol, "initialize first")),
        })?;
        self.shared.served(id).ok_or_else(|| {
            RpcError::fault(Fault::new(
                FaultKind::Connection,
                "the database was closed in the GUI",
            ))
        })
    }

    /// The answer to `method` with `params`.
    fn answer(&mut self, method: &str, params: Value) -> Result<Value, RpcError> {
        if method == method::INITIALIZE {
            return self.initialize(&self::params(params)?);
        }
        let served = self.served()?;
        if method.starts_with("edits.") {
            return self.edit(&served.host, method, params);
        }
        if method == method::PRESENCE
            || method == method::MEMBERS
            || method.starts_with("threads.")
            || method.starts_with("suggestions.")
        {
            return self.session_method(&served, method, params);
        }
        let host = &served.host;
        let faulted = RpcError::fault;
        match method {
            method::SUBSCRIBE => {
                let subscribe: Subscribe = self::params(params)?;
                self.subscribe(host, &subscribe.kinds);
                Ok(Value::Null)
            }
            method::CURSOR => {
                let ui = ui(&served)?;
                let cursor: Cursor = self::params(params)?;
                if let Some(address) = cursor.address {
                    ui.goto(address);
                    return result(&Cursor {
                        address: Some(address),
                    });
                }
                result(&Cursor {
                    address: ui.cursor(),
                })
            }
            method::SELECTION => {
                let selection = ui(&served)?.selection();
                result(&selection.map(|(start, end)| Span { start, end }))
            }
            method::FUNCTIONS => {
                let list: ListFunctions = self::params(params)?;
                result(&functions(&host.session(), list).map_err(faulted)?)
            }
            method::ENTRIES => {
                let session = host.session();
                let database = analysed(&session).map_err(faulted)?;
                let mut entries: Vec<u64> = database
                    .functions()
                    .map(|(_, function)| function.entry)
                    .collect();
                entries.sort_unstable();
                let bytes: Vec<u8> = entries.iter().flat_map(|e| e.to_le_bytes()).collect();
                result(&Entries {
                    entries: base64::encode(&bytes),
                    revision: RevisionData::from(session.revision()),
                })
            }
            method::FUNCTION => {
                let at: At = self::params(params)?;
                let session = host.session();
                let database = analysed(&session).map_err(faulted)?;
                result(
                    &database
                        .function_at(at.address)
                        .map(|id| describe(&session, database, id, at.address)),
                )
            }
            method::CONTAINING => {
                let at: At = self::params(params)?;
                result(&containing(&host.session(), at.address).map_err(faulted)?)
            }
            method::NAME => {
                let at: At = self::params(params)?;
                result(&host.session().name(at.address))
            }
            method::COMMENTS => result(&notes(&host.session().overlay().comments)),
            method::BOOKMARKS => result(&notes(&host.session().overlay().bookmarks)),
            method::TEXT => {
                let text: Text = self::params(params)?;
                result(&c_text(&host.session(), text).map_err(faulted)?)
            }
            method::CHANGES_SINCE => {
                let since: ChangesSince = self::params(params)?;
                let known = sync::vector(&since.frontier).map_err(faulted)?;
                let session = host.lineage().session();
                let changes = sync::changes_since(&session, &known)
                    .iter()
                    .map(sync::encode)
                    .collect();
                result(&Changes {
                    binding: sync::binding(&session),
                    changes,
                })
            }
            _ => Err(no_method(method)),
        }
    }

    /// The answer to `edits.*` method `method` with `params`: the
    /// connection's transactions and writes through `host`.
    fn edit(&self, host: &Host, method: &str, params: Value) -> Result<Value, RpcError> {
        let owner = self.owner;
        let faulted = RpcError::fault;
        match method {
            method::BEGIN => {
                let begin: Begin = self::params(params)?;
                let origin = match begin.author.as_deref() {
                    Some(author) => origin(author)?,
                    None => self.origin.clone(),
                };
                host.begin(owner, &begin.label, origin, self.by())
                    .map_err(faulted)?;
                Ok(Value::Null)
            }
            method::COMMIT => {
                let committed = host.commit(owner).map_err(faulted)?;
                result(&CommitResult {
                    entry: committed.entry,
                    reanalysing: committed.reanalysing,
                })
            }
            method::ROLLBACK => {
                host.rollback(owner).map_err(faulted)?;
                Ok(Value::Null)
            }
            method::APPLY => {
                let apply: Apply = self::params(params)?;
                result(
                    &host
                        .apply(owner, &self.origin, self.by(), &apply.write)
                        .map_err(faulted)?,
                )
            }
            method::UNDO => result(&host.undo().map_err(faulted)?),
            method::REDO => result(&host.redo().map_err(faulted)?),
            method::HISTORY => result(&host.history()),
            method::SETTLE => {
                let settle: Settle = self::params(params)?;
                result(
                    &host
                        .settle(Duration::from_millis(settle.timeout_ms))
                        .map_err(faulted)?,
                )
            }
            _ => Err(no_method(method)),
        }
    }

    /// The handshake: the version chosen, the database attached.
    fn initialize(&mut self, initialize: &Initialize) -> Result<Value, RpcError> {
        let protocol = negotiate(initialize.protocol).map_err(RpcError::fault)?;
        let databases = self.shared.infos();
        let chosen = match initialize.database {
            Some(id) => databases.iter().find(|info| info.id == id).ok_or_else(|| {
                RpcError::fault(Fault::new(
                    FaultKind::Ambiguous,
                    format!("no database {id} is served"),
                ))
            })?,
            None => match databases.as_slice() {
                [only] => only,
                [] => {
                    return Err(RpcError::fault(Fault::new(
                        FaultKind::Ambiguous,
                        "no database is open",
                    )));
                }
                // The one whose window had the focus last (else the last
                // opened).
                several => several
                    .iter()
                    .max_by_key(|info| (info.focused, info.id))
                    .ok_or_else(|| {
                        RpcError::fault(Fault::new(FaultKind::Ambiguous, "no database is open"))
                    })?,
            },
        }
        .clone();
        if let Some(author) = initialize.author.as_deref() {
            self.origin = origin(author)?;
        }
        if let Some(hello) = &initialize.agent {
            let name = hello.name.trim();
            if name.is_empty() {
                return Err(RpcError::fault(Fault::new(
                    FaultKind::Protocol,
                    "an agent needs a name",
                )));
            }
            let served = self.shared.served(chosen.id).ok_or_else(|| {
                RpcError::fault(Fault::new(
                    FaultKind::Connection,
                    "the database was closed in the GUI",
                ))
            })?;
            let key = served
                .host
                .lineage()
                .session()
                .add_agent(name)
                .map_err(|error| RpcError::fault(Fault::session(&error, None)))?;
            let agent = ConnectedAgent {
                key,
                name: name.to_owned(),
                version: hello.version.clone(),
            };
            self.origin = Origin::Agent;
            self.shared.agents().insert(self.owner, (chosen.id, key));
            if let Some(ui) = &served.ui {
                ui.agent(self.owner, Some(agent.clone()));
            }
            self.agent = Some(agent);
        }
        let mut capabilities: Vec<String> =
            capability::SERVED.iter().map(|&c| c.to_owned()).collect();
        if self
            .shared
            .served(chosen.id)
            .is_some_and(|served| served.ui.is_some())
        {
            capabilities.push(capability::UI.to_owned());
        }
        let identity = self
            .shared
            .served(chosen.id)
            .map(|served| served.host.session().identity().to_string());
        self.database = Some(chosen.id);
        result(&Initialized {
            server: self.shared.name.clone(),
            protocol,
            engine: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities,
            databases,
            database: chosen,
            identity,
            agent: self.agent.as_ref().map(|agent| agent.key.to_string()),
        })
    }

    /// The agent key its writes are signed by, if it is an agent.
    fn by(&self) -> Option<PublicKey> {
        self.agent.as_ref().map(|agent| agent.key)
    }

    /// The answer to `threads.*`, `suggestions.*`, `presence.set` (an
    /// agent's place, to the window) or `session.members`.
    fn session_method(
        &self,
        served: &Served,
        method: &str,
        params: Value,
    ) -> Result<Value, RpcError> {
        if method == method::MEMBERS {
            return result(&self.members(served));
        }
        if method != method::PRESENCE {
            return talk::answer(
                &served.host,
                self.owner,
                &self.origin,
                self.by(),
                method,
                params,
            )
            .map_err(RpcError::fault);
        }
        let presence: Presence = self::params(params)?;
        if self.agent.is_some()
            && let Some(ui) = &served.ui
        {
            ui.agent_at(self.owner, presence.address);
        }
        Ok(Value::Null)
    }

    /// Who is in the session of `served`: the people its window knows
    /// (else the server's own user), and the agents its install signs
    /// for, online while one of their connections is.
    fn members(&self, served: &Served) -> Vec<Member> {
        let people = match &served.ui {
            Some(ui) => ui.people(),
            None => Vec::new(),
        };
        let connected: Vec<PublicKey> =
            self.shared.agents().values().map(|&(_, key)| key).collect();
        members(&served.host.session(), people, &connected)
    }

    /// Starts sending the lineage's events of `kinds` (all if empty) as
    /// notifications, until the connection ends.
    fn subscribe(&mut self, host: &Host, kinds: &[String]) {
        if self.subscribed {
            return;
        }
        self.subscribed = true;
        let received = host.lineage().subscribe(None);
        let lineage = Arc::downgrade(host.lineage());
        let writer = Arc::clone(&self.writer);
        let closed = Arc::clone(&self.closed);
        let wanted = |kind: &str| kinds.is_empty() || kinds.iter().any(|k| k == kind);
        let wants = [
            wanted(notification::HISTORY),
            wanted(notification::CHANGED),
            wanted(notification::STAGE),
            wanted(notification::REANALYSED),
            wanted(talk::notification::THREAD),
            wanted(talk::notification::MENTIONED),
        ];
        let _ = thread::Builder::new()
            .name("binbun-notifications".to_owned())
            .spawn(move || {
                while !closed.load(Ordering::Relaxed) {
                    let event = match received.recv_timeout(Duration::from_millis(200)) {
                        Ok(event) => event,
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(RecvTimeoutError::Disconnected) => break,
                    };
                    let Some(lineage) = lineage.upgrade() else {
                        break;
                    };
                    let note = notify(&lineage.session(), &event, wants);
                    drop(lineage);
                    if let Some(note) = note
                        && !send(&writer, &note)
                    {
                        break;
                    }
                }
            });
    }
}

/// `event` as a notification, if it is one of those `wants` (history,
/// changed, stage, reanalysed, thread, mentioned).
fn notify(session: &Session, event: &Event, wants: [bool; 6]) -> Option<Message> {
    let [history, changed, stage, reanalysed, thread, mentioned] = wants;
    let (method, params) = match event {
        Event::History(entries) if history => (
            notification::HISTORY,
            serde_json::to_value(HistoryNote {
                entries: entries
                    .iter()
                    .map(|entry| HistoryItem::of(entry, &[]))
                    .collect(),
            }),
        ),
        Event::Changed(change) if changed => {
            let functions = session
                .database()
                .map(|database| {
                    change
                        .documents
                        .iter()
                        .filter_map(|&id| database.function(id).map(|f| f.entry))
                        .collect()
                })
                .unwrap_or_default();
            (
                notification::CHANGED,
                serde_json::to_value(ChangedNote {
                    functions,
                    listing: change
                        .listing
                        .iter()
                        .map(|range| Span {
                            start: range.start,
                            end: range.end,
                        })
                        .collect(),
                }),
            )
        }
        Event::Stage(reached) if stage => (
            notification::STAGE,
            serde_json::to_value(StageNote {
                stage: stage_number(*reached),
            }),
        ),
        Event::Reanalysed { revision, .. } if reanalysed => (
            notification::REANALYSED,
            serde_json::to_value(ReanalysedNote {
                revision: RevisionData::from(*revision),
            }),
        ),
        Event::Thread(talked) if thread => (
            talk::notification::THREAD,
            serde_json::to_value(ThreadNote::of(talked)),
        ),
        Event::Mentioned(note) if mentioned => (
            talk::notification::MENTIONED,
            serde_json::to_value(MentionedNote::of(note)),
        ),
        Event::History(_)
        | Event::Changed(_)
        | Event::Stage(_)
        | Event::Reanalysed { .. }
        | Event::Thread(_)
        | Event::Mentioned(_)
        | Event::Bookmarks
        | Event::Progress { .. }
        | Event::Document { .. }
        | Event::Unresolved(_)
        | Event::Symbols(_)
        | Event::Answer { .. }
        | Event::Failed(_)
        | Event::Conflicts(_) => return None,
    };
    params
        .ok()
        .map(|params| Message::notification(method, params))
}

/// Who is in `session`'s session (`session.members`): `people` (as a
/// window knows them; else the session's own user, first), and the agents
/// its install signs for, online while one of their keys is `connected`.
pub fn members(session: &Session, people: Vec<Member>, connected: &[PublicKey]) -> Vec<Member> {
    let mut members = people;
    let me = session.identity().to_string();
    if !members.iter().any(|m| m.key == me) {
        members.insert(
            0,
            Member {
                key: me,
                name: std::env::var("USER")
                    .or_else(|_| std::env::var("USERNAME"))
                    .unwrap_or_else(|_| "you".to_owned()),
                kind: "person".to_owned(),
                role: None,
                online: true,
                you: true,
            },
        );
    }
    for (key, name) in session.agents() {
        let online = connected.contains(&key);
        let text = key.to_string();
        match members.iter_mut().find(|m| m.key == text) {
            Some(member) => {
                "agent".clone_into(&mut member.kind);
                member.online |= online;
            }
            None => members.push(Member {
                key: text,
                name,
                kind: "agent".to_owned(),
                role: None,
                online,
                you: false,
            }),
        }
    }
    members
}

/// The origin `author` names.
fn origin(author: &str) -> Result<Origin, RpcError> {
    Origin::parse(author).ok_or_else(|| {
        RpcError::fault(Fault::new(
            FaultKind::Protocol,
            format!("author {author:?}: user, agent, script:<name> or plugin:<id>"),
        ))
    })
}

/// The GUI's side of the database `served`.
fn ui(served: &Served) -> Result<&Arc<dyn Ui>, RpcError> {
    served.ui.as_ref().ok_or_else(|| {
        RpcError::fault(Fault::new(
            FaultKind::Capability,
            "this server has no GUI: no ui.cursor",
        ))
    })
}

/// The functions recovered, once they are.
fn analysed(session: &Session) -> Result<&Engine<'_>, Fault> {
    session.database().ok_or_else(|| {
        Fault::new(
            FaultKind::NotAnalysed,
            "the functions are not recovered yet",
        )
    })
}

/// Function `id` (entry `entry`) as the cheap reads give it.
fn describe(session: &Session, database: &Engine<'_>, id: FunctionId, entry: u64) -> FunctionInfo {
    let edits = session.edits();
    let user_name = edits.name(entry).map(str::to_owned);
    let name = user_name.clone().unwrap_or_else(|| {
        database
            .data_name(entry)
            .unwrap_or_else(|| format!("sub_{entry:X}"))
    });
    let program = database.program();
    let mut ranges: Vec<(u64, u64)> = database
        .function(id)
        .map(|function| {
            function
                .blocks
                .iter()
                .filter_map(|&block| program.blocks.get(block).map(|b| (b.start, b.end)))
                .collect()
        })
        .unwrap_or_default();
    ranges.sort_unstable();
    let mut merged: Vec<Span> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.end => last.end = last.end.max(end),
            _ => merged.push(Span { start, end }),
        }
    }
    FunctionInfo {
        entry,
        name,
        user_name,
        name_source: session
            .name_source(entry)
            .map(|source| source.name().to_owned()),
        ranges: merged,
    }
}

/// A page of the functions.
fn functions(session: &Session, list: ListFunctions) -> Result<FunctionPage, Fault> {
    let database = analysed(session)?;
    let mut entries: Vec<(u64, FunctionId)> = database
        .functions()
        .map(|(id, function)| (function.entry, id))
        .filter(|&(entry, _)| list.after.is_none_or(|after| entry > after))
        .collect();
    entries.sort_unstable();
    let limit = list.limit.max(1);
    let next = (entries.len() > limit)
        .then(|| entries.get(limit - 1).map(|&(entry, _)| entry))
        .flatten();
    entries.truncate(limit);
    Ok(FunctionPage {
        items: entries
            .into_iter()
            .map(|(entry, id)| describe(session, database, id, entry))
            .collect(),
        next,
        revision: RevisionData::from(session.revision()),
    })
}

/// The comments or bookmarks `notes`, by address.
fn notes(notes: &BTreeMap<u64, String>) -> Vec<Note> {
    notes
        .iter()
        .map(|(&address, text)| Note {
            address,
            text: text.clone(),
        })
        .collect()
}

/// The functions with a block holding the instruction at `address`, by
/// entry (blocks can be shared; none outside every function).
fn containing(session: &Session, address: u64) -> Result<Vec<FunctionInfo>, Fault> {
    let database = analysed(session)?;
    let Some(block) = database.program().block_containing(address) else {
        return Ok(Vec::new());
    };
    let mut held: Vec<(u64, FunctionId)> = database
        .functions()
        .filter(|(_, function)| function.blocks.contains(&block))
        .map(|(id, function)| (function.entry, id))
        .collect();
    held.sort_unstable();
    Ok(held
        .into_iter()
        .map(|(entry, id)| describe(session, database, id, entry))
        .collect())
}

/// A function's C as text.
fn c_text(session: &Session, text: Text) -> Result<String, Fault> {
    let database = analysed(session)?;
    let id = database.function_at(text.entry).ok_or_else(|| {
        Fault::new(
            FaultKind::NoFunction,
            format!("no function starts at {:#x}", text.entry),
        )
    })?;
    session
        .document_view(id, text.view.view())
        .map(|document| document.text.clone())
        .map_err(|message| Fault::new(FaultKind::Decompile, message))
}
