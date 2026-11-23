//! A shared session's network side in a binbun built without the
//! `collab` feature: no peer can be made ([`Net::share`] and
//! [`Net::join`] say so), so none of the rest is ever reached. The same
//! types as `collab_net.rs`, so the window is the same in both builds.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use binbun_gui_view::chat::ChatLink;
use binbun_gui_view::collab::{Analysis, ChatLine, Cursor, Fetching, Offered, Person, Role};
use binbun_gui_view::session::Wake;
use binbun_gui_view::settings::CollabRelay;
use binbun_gui_view::sharing::Listed;
use binbun_session::Session;
use binbun_session::identity::Identity;
use binbun_session::journal::{ChainId, EngineVersion, PublicKey, Refused};

/// Why there is no network side.
const WITHOUT: &str = "this binbun was built without collaboration (the `collab` feature)";

/// How long stopping would wait for those linked.
pub const FLUSH: Duration = Duration::from_secs(5);

/// What is told what a flush came to.
pub type Report = Box<dyn FnOnce([Vec<PublicKey>; 3]) + Send>;

/// How a host is reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// The `collab.relay` setting's relay.
    #[default]
    Relay,
    /// No relay.
    NoRelay,
    /// The LAN only.
    Lan,
}

impl Mode {
    /// Its label in the Share and Join dialogs, with `relay` the setting's.
    pub fn label(self, relay: &CollabRelay) -> &'static str {
        match self {
            Self::Relay => relay.label(),
            Self::NoRelay => "No relay",
            Self::Lan => "LAN only",
        }
    }
}

/// Someone asking to join.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked {
    /// The request's number.
    pub id: u64,
    /// Their identity key.
    pub key: PublicKey,
    /// Their name.
    pub name: String,
    /// How their link reaches this peer.
    pub path: String,
    /// The binbun they run.
    pub engine: EngineVersion,
}

/// What the network side tells the window.
#[derive(Clone, Debug)]
#[expect(dead_code, reason = "no network side makes them in this build")]
pub enum NetEvent {
    /// Sharing: the ticket.
    Ticket(String),
    /// Someone asks to join.
    Asked(Asked),
    /// A request to join withdrawn.
    Withdrawn(u64),
    /// A status line.
    Said(String),
    /// The session is over.
    Ended(String),
    /// This peer is view-only.
    ViewOnly(String),
    /// Something failed.
    Failed(String),
    /// Changes came.
    Took,
    /// A change was refused.
    Refused,
    /// The membership changed.
    Members,
    /// A cursor moved.
    Cursor(PublicKey, Cursor),
    /// Someone came or left.
    People,
    /// A chat message.
    Chat(ChatLine),
    /// The owner removed a chat message.
    ChatRemoved(u64),
    /// The host sends a binary this window lacks.
    Offer(Offered),
    /// A fetch under way.
    Fetching(Fetching),
    /// A file fetched.
    Fetched {
        /// Whether it is a debug file.
        debug: bool,
        /// Where it is.
        path: PathBuf,
        /// The slice to open, of a universal binary.
        arch: Option<String>,
        /// The project directory to open it in.
        project: Option<PathBuf>,
    },
    /// A fetch failed.
    FetchFailed(String),
}

/// What a sharer sends to those who join.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sends {
    /// The binary.
    pub binary: bool,
    /// The debug file.
    pub debug: bool,
}

/// What the window makes of a binary offered that it lacks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Fetch it.
    Fetch,
    /// Join with this file instead.
    Open(PathBuf),
    /// Do not join.
    Cancel,
}

/// No network side: never made.
#[derive(Debug)]
pub struct Net(Infallible);

/// The name a card carries by default: the login.
pub fn default_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "someone".to_owned())
}

/// Says this binbun has no identity card.
///
/// # Errors
///
/// Always: built without collaboration.
pub fn my_card(_: &str) -> Result<String, String> {
    Err(WITHOUT.to_owned())
}

/// No history to list: this binbun cannot share.
///
/// # Errors
///
/// Always: built without collaboration.
pub fn listable(_: &Session) -> Result<Option<Vec<Listed>>, String> {
    Err(WITHOUT.to_owned())
}

/// Says this binbun reads no identity card.
///
/// # Errors
///
/// Always: built without collaboration.
pub fn card_of(_: &str) -> Result<(PublicKey, String), String> {
    Err(WITHOUT.to_owned())
}

impl Net {
    /// Says this binbun cannot share.
    ///
    /// # Errors
    ///
    /// Always: built without collaboration.
    #[expect(clippy::too_many_arguments, reason = "the same as the network side's")]
    pub fn share(
        _: Arc<Session>,
        _: &str,
        _: Mode,
        _: &CollabRelay,
        _: Sends,
        _: Vec<(String, Role)>,
        _: Option<BTreeSet<ChainId>>,
        _: Wake,
    ) -> Result<Self, String> {
        Err(WITHOUT.to_owned())
    }

    /// Whether `ticket` asks for the LAN only: not known here.
    pub fn lan_only(_: &str) -> Option<bool> {
        None
    }

    /// Says this binbun cannot join.
    ///
    /// # Errors
    ///
    /// Always: built without collaboration.
    pub fn join(
        _: Option<Arc<Session>>,
        _: &str,
        _: &str,
        _: Mode,
        _: &CollabRelay,
        _: Wake,
    ) -> Result<Self, String> {
        Err(WITHOUT.to_owned())
    }

    /// Never reached.
    pub fn decide(&self, _: Decision) {
        match self.0 {}
    }

    /// Never reached.
    pub fn send(&self, _: bool, _: bool) {
        match self.0 {}
    }

    /// Never reached.
    pub fn fetch_debug(&self, _: PublicKey) {
        match self.0 {}
    }

    /// Never reached.
    pub fn poll(&self) -> Vec<NetEvent> {
        match self.0 {}
    }

    /// Never reached.
    pub fn me(&self) -> PublicKey {
        match self.0 {}
    }

    /// Never reached.
    pub fn hosting(&self) -> bool {
        match self.0 {}
    }

    /// Never reached.
    pub fn project(&self) -> Option<String> {
        match self.0 {}
    }

    /// Never reached.
    pub fn role(&self) -> Option<Role> {
        match self.0 {}
    }

    /// Never reached.
    pub fn read_only(&self) -> Option<String> {
        match self.0 {}
    }

    /// Never reached.
    pub fn people(&self) -> Vec<Person> {
        match self.0 {}
    }

    /// Never reached.
    pub fn admitted(&self) -> Vec<PublicKey> {
        match self.0 {}
    }

    /// Never reached.
    pub fn members(&self) -> Vec<(PublicKey, Role)> {
        match self.0 {}
    }

    /// Never reached.
    ///
    /// # Errors
    ///
    /// Never.
    pub fn add_card(&self, _: &str, _: Role) -> Result<(PublicKey, String), String> {
        match self.0 {}
    }

    /// Never reached.
    pub fn owner(&self) -> Option<PublicKey> {
        match self.0 {}
    }

    /// Never reached.
    pub fn joining(&self) -> bool {
        match self.0 {}
    }

    /// Never reached.
    ///
    /// # Errors
    ///
    /// Never.
    pub fn chat(&self, _: &str, _: &[ChatLink], _: &[PublicKey]) -> Result<(), String> {
        match self.0 {}
    }

    /// Never reached.
    ///
    /// # Errors
    ///
    /// Never.
    pub fn remove_chat(&self, _: u64) -> Result<(), String> {
        match self.0 {}
    }

    /// Never reached.
    pub fn set_cursor(&self, _: Cursor) {
        match self.0 {}
    }

    /// Never reached.
    pub fn host_agents(&self, _: &[(Identity, Person)]) {
        match self.0 {}
    }

    /// Never reached.
    pub fn follow(&self, _: Option<PublicKey>) {
        match self.0 {}
    }

    /// Never reached.
    pub fn announce(&self, _: Option<&Analysis>) {
        match self.0 {}
    }

    /// Never reached.
    pub fn answer(&self, _: u64, _: Option<Role>) {
        match self.0 {}
    }

    /// Never reached.
    ///
    /// # Errors
    ///
    /// Never.
    pub fn set_role(&self, _: PublicKey, _: Role) -> Result<(), String> {
        match self.0 {}
    }

    /// Never reached.
    ///
    /// # Errors
    ///
    /// Never.
    pub fn remove(&self, _: PublicKey) -> Result<(), String> {
        match self.0 {}
    }

    /// Never reached.
    ///
    /// # Errors
    ///
    /// Never.
    pub fn add_agent(&self, _: &Identity, _: &str) -> Result<(), String> {
        match self.0 {}
    }

    /// Never reached.
    pub fn refused(&self) -> Vec<Refused> {
        match self.0 {}
    }

    /// Never reached.
    pub fn set_session(&self, _: Arc<Session>) {
        match self.0 {}
    }

    /// Never reached.
    pub fn stop(self, _: Duration, _: Option<Report>) {
        match self.0 {}
    }
}
