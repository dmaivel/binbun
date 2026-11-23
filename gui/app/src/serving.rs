//! The GUI's server (`binbun-protocol`'s): scripts reach the binaries the
//! windows show over the user's own
//! socket (`binbun.connect()`), writing through each session's host as
//! the GUI's edits do. Started with the first binary opened, stopped when
//! the app quits; each window's cursor and selection are kept here as
//! plain data for `ui.cursor` and `ui.selection`, and a script's move of
//! the cursor reaches the window as a jump. The agents connected (an
//! agent's harness through `binbun mcp`) are kept here too, with where
//! each one's code works, for the window to show among the participants;
//! and the people as the window knows them, for `session.members`. The
//! window focused last is told to the server: `binbun mcp` attaches there.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_channel::Sender;
use binbun_gui_view::session::Session;
use binbun_protocol::discovery;
use binbun_protocol::messages::Member;
use binbun_protocol::server::{ConnectedAgent, Server, Ui};
use binbun_session::journal::PublicKey;

/// The process's server, once started.
static SERVER: Mutex<Option<Server>> = Mutex::new(None);

fn server() -> MutexGuard<'static, Option<Server>> {
    SERVER.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Locks `mutex`, poisoned or not.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a window shows, for scripts: its cursor and selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Shown {
    cursor: Option<u64>,
    selection: Option<(u64, u64)>,
}

/// What the server tells a window, on its thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Told {
    /// A script moved the cursor here: the window jumps there.
    Goto(u64),
    /// An agent came, went or moved ([`WindowUi::agents`]).
    Agents,
}

/// One agent connection.
#[derive(Clone, Debug)]
struct Connection {
    agent: ConnectedAgent,
    /// Where its code works.
    at: Option<u64>,
    /// When it last moved (the window's count of moves).
    moved: u64,
}

/// An agent connected, as the window shows it: one per key, however
/// many connections it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentHere {
    /// Its identity key.
    pub key: PublicKey,
    /// Its name, as it said.
    pub name: String,
    /// Its version, if it said.
    pub version: Option<String>,
    /// Where its code works now (its connection that moved last).
    pub at: Option<u64>,
}

/// A window's side of `ui.cursor` and `ui.selection`, its agents and its
/// people.
#[derive(Debug)]
pub struct WindowUi {
    shown: Mutex<Shown>,
    /// The agents connected, by connection.
    agents: Mutex<BTreeMap<u64, Connection>>,
    /// How many moves the agents made (orders them).
    moves: AtomicU64,
    /// The people as the window last said them.
    people: Mutex<Vec<Member>>,
    /// Where the window hears of jumps and agents.
    told: Sender<Told>,
}

impl WindowUi {
    /// A window's, that hears of jumps and agents through `told`.
    pub fn new(told: Sender<Told>) -> Self {
        Self {
            shown: Mutex::new(Shown::default()),
            agents: Mutex::new(BTreeMap::new()),
            moves: AtomicU64::new(0),
            people: Mutex::new(Vec::new()),
            told,
        }
    }

    /// The window shows its cursor at `cursor`, `selection` selected.
    pub fn show(&self, cursor: Option<u64>, selection: Option<(u64, u64)>) {
        *lock(&self.shown) = Shown { cursor, selection };
    }

    /// The agents connected, one per key in the order they connected:
    /// the name and version of its first connection, the place of the one
    /// that moved last.
    pub fn agents(&self) -> Vec<AgentHere> {
        let connections = lock(&self.agents);
        let mut out: Vec<(AgentHere, u64)> = Vec::new();
        for connection in connections.values() {
            match out.iter_mut().find(|(a, _)| a.key == connection.agent.key) {
                Some((here, moved)) => {
                    if connection.moved > *moved && connection.at.is_some() {
                        here.at = connection.at;
                        *moved = connection.moved;
                    }
                }
                None => out.push((
                    AgentHere {
                        key: connection.agent.key,
                        name: connection.agent.name.clone(),
                        version: connection.agent.version.clone(),
                        at: connection.at,
                    },
                    connection.moved,
                )),
            }
        }
        out.into_iter().map(|(here, _)| here).collect()
    }

    /// The people as the window knows them now (`Ui::people`).
    pub fn set_people(&self, people: Vec<Member>) {
        *lock(&self.people) = people;
    }
}

impl Ui for WindowUi {
    fn cursor(&self) -> Option<u64> {
        lock(&self.shown).cursor
    }

    fn goto(&self, address: u64) {
        let _ = self.told.try_send(Told::Goto(address));
    }

    fn selection(&self) -> Option<(u64, u64)> {
        lock(&self.shown).selection
    }

    fn agent(&self, connection: u64, agent: Option<ConnectedAgent>) {
        {
            let mut agents = lock(&self.agents);
            match agent {
                Some(agent) => {
                    agents.insert(
                        connection,
                        Connection {
                            agent,
                            at: None,
                            moved: 0,
                        },
                    );
                }
                None => {
                    agents.remove(&connection);
                }
            }
        }
        let _ = self.told.try_send(Told::Agents);
    }

    fn agent_at(&self, connection: u64, address: Option<u64>) {
        {
            let mut agents = lock(&self.agents);
            let Some(connection) = agents.get_mut(&connection) else {
                return;
            };
            if connection.at == address {
                return;
            }
            connection.at = address;
            connection.moved = self.moves.fetch_add(1, Ordering::Relaxed) + 1;
        }
        let _ = self.told.try_send(Told::Agents);
    }

    fn people(&self) -> Vec<Member> {
        lock(&self.people).clone()
    }
}

/// Serves `session`'s binary, its window's side `ui` (the server started
/// first if it is not); its number there.
///
/// # Errors
///
/// No `XDG_RUNTIME_DIR` (on Windows, nor `LOCALAPPDATA`), its `binbun`
/// directory open to others, or the socket (on Windows the named pipe) or
/// discovery file cannot be made (why).
pub fn serve(session: &Session, ui: Arc<WindowUi>) -> Result<u64, String> {
    let mut server = server();
    if server.is_none() {
        let started = discovery::dir()
            .and_then(|dir| Server::start(&dir, concat!("binbun-gui/", env!("CARGO_PKG_VERSION"))));
        *server = Some(started.map_err(|fault| format!("scripts cannot connect: {fault}"))?);
    }
    let Some(server) = server.as_ref() else {
        return Err("scripts cannot connect: no server".to_owned());
    };
    server
        .add(session.path(), Arc::clone(session.host()), Some(ui))
        .map_err(|fault| format!("scripts cannot connect: {fault}"))
}

/// Database `id`'s window got the focus: `binbun mcp` and `connect()`
/// without a target attach to it.
pub fn focus(id: u64) {
    if let Some(server) = server().as_ref() {
        let _ = server.focus(id);
    }
}

/// Serves database `id` no more (its window closed it).
pub fn withdraw(id: u64) {
    if let Some(server) = server().as_ref() {
        let _ = server.remove(id);
    }
}

/// Stops the server: its socket and discovery file removed.
pub fn stop() {
    drop(server().take());
}

/// The server's socket, once it is started (the console connects to it).
pub fn socket() -> Option<std::path::PathBuf> {
    server().as_ref().map(|server| server.socket().to_owned())
}
