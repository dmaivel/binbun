//! One opened binary for an interactive front end, framework-free: a
//! [`Session`] owns the
//! file's bytes, the [`Image`] parsed from them and the [`Database`]
//! recovered from it, analyses on a worker thread, serves functions' C on
//! request, keeps the user's edits and tells subscribers what changed.
//!
//! - **Opening** returns at once; the worker reads the file, parses it
//!   while a thread of its own hashes it (its [`Key`]: SHA-256 and file
//!   name, naming its [`project`]), loads the project's edits
//!   ([`Session::project`]; [`Stage::Image`]: [`Session::image`]),
//!   recovers the functions
//!   ([`Stage::Analysed`]: [`Session::database`], what a listing needs),
//!   builds the cross-references ([`Stage::Referenced`]) and what callers
//!   read of each function, with every function's interface
//!   ([`Stage::Callers`]: every request now costs only its function's own
//!   work), then goes through the functions callees first
//!   ([`Database::warm`], which finds nothing more once the interfaces
//!   are found; [`Stage::Warmed`]).
//! - **Debug information** ([`Options::debug`]) is read before the
//!   functions are recovered and taken as `binbun decompile --debug` takes
//!   it: from the file given, else where the documented conventions put
//!   it ([`binbun_debuginfo::info::locate`]: the image's own DWARF, build ID,
//!   `.gnu_debuglink`, the debuginfod cache; the PDB the `CodeView`
//!   record names). [`Session::debug_file`] says which file it came from,
//!   [`Session::source_unit`] each function's compilation unit.
//! - **Symbol servers** ([`Options::symbols`], [`Symbols`]): searched
//!   for and not found where the conventions put it, the debug
//!   information is taken from a local symbol store if one has it (nothing
//!   sent); else, as [`Download`] says, offered ([`SymbolState::Available`]:
//!   fetched when [`Session::fetch_symbols`] is called), fetched at once on
//!   a thread of its own, or never fetched; the analysis never waits for
//!   it. Each step is told as [`Event::Symbols`]. A fetched file is taken
//!   by decompiling again: [`Session::with_debug`] opens the binary anew
//!   with it and the edits; [`Session::take_edits`] then takes those made
//!   meanwhile in the session it replaces.
//! - **Corrections** of what recovery found ([`Corrections`]: code, bytes
//!   undefined, data, a function made, its end, a function deleted) are
//!   edits too ([`Session::set_corrections`], each new one checked against
//!   the program first and refused with the reason), and inputs of
//!   recovery: whether callees return decides code everywhere, so none is
//!   applied in place; [`Session::reanalysed`] opens the binary anew with
//!   them (its bytes and image not read again), to take the place of this
//!   one as [`Session::with_debug`]'s does.
//! - **Requests** for a function's C ([`Session::request`],
//!   [`Session::document`]) come before the warming: the worker serves
//!   every request waiting before warming the next function. A function
//!   is decompiled once (its L2 kept) and printed with the user's names
//!   ([`Document`]); without edits its text is `binbun decompile`'s.
//!   A request names a [`View`] ([`Session::request_view`]; without one,
//!   [`Options::view`]): the exact C or the reading view, each decompiled
//!   and kept on its own. A document carries each variable's default name
//!   ([`Document::default_name`]).
//! - **Cancelling** ([`Session::cancel`], [`Session::close`], dropping the
//!   session) stops the worker at its next step: between stages, requests
//!   and functions warmed (a stage itself, a whole-program pass, runs to
//!   its end).
//! - **Questions** about a function's C ([`Session::ask`], [`Question`]):
//!   verify, why, origin, run with values, the stages of its
//!   decompilation (the IR viewer's), and the call graph's (its
//!   callers and callees with their C lines and arguments' known
//!   values, [`CallSite`]; paths from it, [`PathRequest`]), answered on
//!   three lanes of their own (verification and the call graph's
//!   apart), each cancellable ([`Asked::cancel`]) and kept per
//!   function, view and question ([`Session::answer`]), told as
//!   [`Event::Answer`].
//! - **Edits** ([`Edits`]) name functions, globals and variables and
//!   comment addresses by identities that survive re-analysis, never by
//!   printed names: a function by its entry, a global or comment by its
//!   address, a variable by its function's entry and what it was made
//!   from ([`Variable`]). A name is presentation: it prints the kept L2
//!   again, never decompiles. Edits are saved (crash-safely) to a TOML
//!   project file in the binary's project ([`project`]: its own directory
//!   in binbun's data directory, keyed by its contents, so a moved,
//!   renamed or copied file keeps it; or where [`Options::project`]
//!   says), and applied again on reopening; one that no longer resolves is kept,
//!   saved and reported ([`Event::Unresolved`], [`Session::unresolved`]).
//! - **Events** ([`Event`]) go to every subscriber ([`Session::subscribe`]
//!   for a channel, [`Session::on_event`] for a callback): stages,
//!   warming progress, documents, and what changed ([`Change`]: the
//!   documents to print again and the listing's address ranges) after an
//!   edit or a stage. A name changes the documents that print it: a
//!   variable's, its function's; a function's or a global's, the
//!   functions referring to it ([`Database::references`]) and the
//!   function itself. A comment (on an instruction's address) changes the
//!   documents of the functions holding the instruction, which print it
//!   at the end of the C lines made from it ([`Document::comments`]).
//! - **Provenance** ([`Provenance`], [`Document::provenance`]): which
//!   instructions each line and token of a document came from, what links
//!   the C to the listing in every front end.
//! - **The listing** ([`Session::listing`], [`listing`]): the continuous
//!   listing of the image built once per options, with the user's names,
//!   comments, bookmarks and numbers' forms laid over it
//!   ([`Session::overlay`]).
//! - **Searches** ([`search`]): text through the listing and every
//!   function's C, immediates, bytes with wildcards, on threads of their
//!   own, streamed.
//! - **Waiting** for a stage ([`Session::wait`]) or an answer
//!   ([`Asked::wait`]), each with a timeout; how far the session is
//!   ([`Session::revision`]: analyses and edits counted).
//! - **Ephemeral** sessions ([`Options::ephemeral`]): no project, the
//!   edits kept in memory only.
//! - **The journal** ([`journal`]): the edits are the projection of a log
//!   of changes signed by this install's identity ([`identity`]), kept
//!   beside the project file; made in groups ([`Session::begin`],
//!   [`Session::commit`], [`Session::rollback`]: one change, one save,
//!   one merged [`Event::Changed`]), undone and made again per author by
//!   compare-and-set ([`Session::undo`], [`Session::redo`],
//!   [`Session::history`]); changes from elsewhere taken
//!   ([`Session::receive`]), concurrent edits shown as conflicts
//!   ([`Session::conflicts`], [`Session::resolve`]).
//! - **Analysing anew** ([`Lineage`]): corrections and debug information
//!   fetched are taken by a new session beside the one in use, swapped in
//!   with the edits made meanwhile ([`Event::Reanalysed`]).
//! - **Conversation** ([`talk`]): threads anchored to addresses, posts and
//!   suggestions in the same journal ([`Session::open_thread`],
//!   [`Session::post`], [`Session::suggest`], [`Session::accept`]), told
//!   as [`Event::Thread`] and [`Event::Mentioned`].
//! - **Bookmarks** across authors: this identity's own
//!   ([`Session::bookmark`], in the overlay), every other's
//!   ([`Session::others_bookmarks`]), and this install's private ones
//!   ([`Session::bookmark_private`], [`Session::set_bookmark_private`]:
//!   local, never sent), told as [`Event::Bookmarks`].
//!
//! ```no_run
//! use binbun_session::{Event, Options, Session, Stage};
//!
//! let session = Session::open("/usr/bin/bash", Options::default())?;
//! let events = session.subscribe(None);
//! for event in &events {
//!     match event {
//!         Event::Stage(Stage::Analysed) => {
//!             // The listing can be built now: `session.database()`.
//!             let database = session.database().expect("analysed");
//!             let (main, _) = database.functions().next().expect("a function");
//!             session.request(main);
//!         }
//!         Event::Document { function, result: Ok(document), .. } => {
//!             println!("{}", document.text);
//!             // `N` on the function's name, then Enter:
//!             let entry = document.entry;
//!             session.rename_function(entry, Some("start"))?;
//!         }
//!         Event::Changed(change) => {
//!             for &function in &change.documents {
//!                 session.request(function);
//!             }
//!             break;
//!         }
//!         _ => {}
//!     }
//! }
//! session.close();
//! # Ok::<(), binbun_session::Error>(())
//! ```

mod bookmarks;
mod calls;
mod cell;
mod document;
mod edits;
mod facts;
mod fingerprint;
pub mod identity;
pub mod journal;
mod lineage;
pub mod listing;
mod members;
pub mod number;
mod processor;
pub mod project;
pub mod provenance;
mod remote;
pub mod search;
pub mod signatures;
mod symbols;
pub mod talk;
mod types;
mod worker;
mod write;

use std::collections::{BTreeSet, HashMap};
use std::error::Error as StdError;
use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use binbun::Database;
use binbun::cfg::FunctionId;
use binbun::decompile::Callers;
use binbun_ast::ir::{Function as Ast, Node, Origin, VarId, VarKind};
use binbun_ast::types::Enumeration;
use binbun_loader::Image;
use binbun_print::c;
use binbun_print::c::Image as _;
use binbun_print::layout::render;
use binbun_print::style::{IntSpelling, Style};

pub use binbun::corrections::{self, Bounds, Corrections, Item};
pub use binbun::decompile::View;
pub use binbun_debuginfo::info::model::Unit;
pub use binbun_print::style::Naming;
pub use binbun_print::style::Placement;
pub use binbun_typedb::c::CError;
pub use calls::CallSite;
pub use document::Document;
pub use edits::{Edit, Edits, Identified, Matched, NumberForm, Typed, Unresolved, Variable};
pub use facts::{Answer, Asked, PathRequest, Question, Unanswered};
pub use fingerprint::{DebugDigest, Fingerprint};
pub use journal::{Applied, Conflict, HistoryEntry, Refused, Skipped, Undone, VersionVector};
pub use lineage::{Lineage, Swapped};
pub use members::{MemberAt, MemberEdit, member_at};
pub use project::{Key, Project};
pub use provenance::Provenance;
pub use symbols::{Download, SymbolState, Symbols};
pub use talk::{Located, Rechecked, Say, Suggesting};
pub use types::{
    EnumLayout, GlobalTable, GlobalTyped, StructLayout, StructMember, Synthesised, TypeLayout,
    definition_in,
};

use cell::Loaded;
use facts::{Answers, Job};
use journal::{Journal, Key as JournalKey, Stated, Value};
use listing::{Listing, Options as ListingOptions, Overlay};
use worker::{DebugInput, Place, Reply, Request, Shared};

/// How far the analysis of an opened binary is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    /// The file is being read and parsed.
    Opening,
    /// The image is parsed ([`Session::image`]).
    Image,
    /// The functions are recovered ([`Session::database`]).
    Analysed,
    /// The cross-references are built ([`Database::references`]).
    Referenced,
    /// The library functions whose identity a signature pack holds
    /// exactly are named ([`Options::signatures`]); checking the others'
    /// behaviour goes on in the background, its names one later change.
    Signatures,
    /// What callers read of each function and every function's interface
    /// are computed ([`Database::callers`]): a function's C costs only
    /// its own work now.
    Callers,
    /// Every function is warmed ([`Database::warm`]), as
    /// [`Self::Callers`] already leaves it.
    Warmed,
}

/// What an edit or a stage changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Change {
    /// The functions whose documents read differently now, in order.
    pub documents: Vec<FunctionId>,
    /// The address ranges whose listing lines read differently now
    /// (an item changes if its first address is in one), sorted and
    /// disjoint.
    pub listing: Vec<Range<u64>>,
}

/// Something a session tells its subscribers.
#[derive(Clone, Debug)]
pub enum Event {
    /// A stage is reached. A new subscriber hears the stage reached first.
    Stage(Stage),
    /// The warming has found `warmed` of `total` functions' interfaces.
    Progress {
        /// Functions warmed.
        warmed: usize,
        /// Functions to warm.
        total: usize,
    },
    /// Documents or listing lines changed.
    Changed(Arc<Change>),
    /// The answer to request `request` ([`Session::request`]).
    Document {
        /// The request.
        request: u64,
        /// The function asked for.
        function: FunctionId,
        /// Its document, or why there is none (as `binbun decompile`
        /// says).
        result: Result<Arc<Document>, String>,
    },
    /// Edits found not to resolve (each once; a new subscriber first hears
    /// those found so far: [`Session::subscribe`]).
    Unresolved(Arc<[Unresolved]>),
    /// What became of the binary's debug information on a symbol server
    /// ([`Options::symbols`]).
    Symbols(SymbolState),
    /// The answer to question `request` ([`Session::ask`]).
    Answer {
        /// The request.
        request: u64,
        /// The function asked about.
        function: FunctionId,
        /// The view.
        view: View,
        /// The answer.
        answer: Answer,
    },
    /// Opening failed, an edit could not be saved, or debug information
    /// was not used (a file given that cannot be read; one where the
    /// conventions put it that is another build's).
    Failed(String),
    /// Changes entered the history (made here, undone, made again, taken
    /// from elsewhere), newest first ([`Session::history`]); none when
    /// changes only left it (a chain frozen: [`Session::freeze`]).
    History(Arc<[HistoryEntry]>),
    /// Concurrent edits left keys with more than one value, or a conflict
    /// was resolved: every conflict now ([`Session::conflicts`]).
    Conflicts(Arc<[Conflict]>),
    /// Conversation came, made here or taken from elsewhere: threads
    /// opened, posted to, resolved; posts edited or deleted; suggestions
    /// made or decided ([`Session::threads`], [`Session::suggestions`]).
    Thread(Arc<talk::Talked>),
    /// A new post mentions this identity (or one it answers for,
    /// [`Session::answer_for`]): the person, or one of its scripts or
    /// agents ([`talk::Mention::agent`]).
    Mentioned(Arc<talk::Mentioned>),
    /// Every other author's bookmarks ([`Session::others_bookmarks`]) or
    /// this install's private ones ([`Session::private_bookmarks`]) may
    /// have changed: changes taken from elsewhere (or dropped by a
    /// freeze) touched another's bookmark, a private bookmark was edited
    /// ([`Session::bookmark_private`]), undone or made again, or a
    /// bookmark moved between shared and private
    /// ([`Session::set_bookmark_private`]). Both are read again.
    Bookmarks,
    /// The binary analysed anew (with corrections, or debug information
    /// fetched) took the place of the one analysed before
    /// ([`Lineage::swap`]); told by the [`Lineage`] only, before what the
    /// new analysis told meanwhile.
    Reanalysed {
        /// The new session's revision.
        revision: Revision,
        /// The functions of the analysis before that the new one has too
        /// (by entry): their ids now, by their ids before.
        functions: Arc<HashMap<FunctionId, FunctionId>>,
    },
}

/// What waiting for a stage came to ([`Session::wait`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Waited {
    /// The stage was reached: the stage reached now (that one or later).
    Reached(Stage),
    /// The time ran out at this stage.
    TimedOut(Stage),
    /// The worker stopped at this stage without reaching it (cancelled,
    /// or opening failed: the failure told last, if one was).
    Stopped {
        /// The stage reached.
        stage: Stage,
        /// The last failure told ([`Event::Failed`]).
        failure: Option<String>,
    },
}

/// How far a session's state has come: what a front end compares to know
/// whether what it read is still current.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revision {
    /// The analyses before this one (a session opened again with
    /// corrections or debug information fetched counts one more than the
    /// one it replaces).
    pub analysis: u64,
    /// The changes made or taken (carried over from the session it
    /// replaces): an edit made alone, a group of edits, an undo.
    pub edits: u64,
}

/// Why a session cannot do something.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The project file cannot be read or written.
    Project(String),
    /// No function starts at this address.
    NoFunction(u64),
    /// The function is not decompiled yet (its variables are known from
    /// its document).
    NotDecompiled(FunctionId),
    /// The function's L2 has no such variable.
    NoVariable(VarId),
    /// The functions are not recovered yet.
    NotAnalysed,
    /// The C of a type is refused.
    Type(CError),
    /// A correction of recovery cannot apply: why.
    Correction(String),
    /// A group of edits cannot be made or is open where none may be: why.
    Transaction(String),
    /// A thread, post or suggestion cannot be written: why.
    Conversation(String),
    /// The share does not take the edit (the role, a removal, a join
    /// under way): why. It is not written and not shown.
    Refused(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Project(message) => write!(f, "project: {message}"),
            Self::NoFunction(entry) => write!(f, "no function starts at {entry:#x}"),
            Self::NotDecompiled(function) => {
                write!(f, "function {function:?} is not decompiled yet")
            }
            Self::NoVariable(var) => write!(f, "no variable {}", var.0),
            Self::NotAnalysed => f.write_str("the functions are not recovered yet"),
            Self::Type(error) => write!(f, "{error}"),
            Self::Correction(why)
            | Self::Transaction(why)
            | Self::Conversation(why)
            | Self::Refused(why) => f.write_str(why),
        }
    }
}

impl StdError for Error {}

/// How a session opens a binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// The project's directory; `None`: the binary's own in
    /// [`Options::projects`], found by its contents ([`project::locate`])
    /// once the file is read.
    pub project: Option<PathBuf>,
    /// Where the binaries' own projects are kept; `None`: binbun's data
    /// directory ([`project::root`]).
    pub projects: Option<PathBuf>,
    /// Whether each edit is saved to the project file as it is made.
    pub autosave: bool,
    /// No project: the edits are kept in memory only, nothing read from a
    /// project or written ([`Session::project`] is `None`, saving
    /// refused); [`Self::project`] and [`Self::projects`] are not used.
    /// The binary is still hashed ([`Session::key`]).
    pub ephemeral: bool,
    /// The style preset the C is laid out in (`binbun decompile`'s
    /// default: `kr`).
    pub style: String,
    /// How the C spells integer types (`binbun decompile --types`; by
    /// default fixed-width). [`Session::set_style`] changes it, and the
    /// rest of the style, in place.
    pub types: IntSpelling,
    /// Where the C declares locals (`binbun decompile --declarations`; by
    /// default in the blocks using them). [`Session::set_style`] changes
    /// it, and the rest of the style, in place.
    pub declarations: Placement,
    /// How the C names variables with no name of their own (`binbun
    /// decompile --names`; by default by kind and number).
    /// [`Session::set_style`] changes it, and the rest of the style, in
    /// place.
    pub names: Naming,
    /// Whether the worker, once idle, warms every function's interfaces
    /// callees first ([`Stage::Warmed`]).
    pub warm: bool,
    /// The view requests without one are answered in
    /// ([`Session::request`], [`Session::document`]): exact by default,
    /// as `binbun decompile`.
    pub view: View,
    /// Where the binary's debug information is.
    pub debug: DebugSource,
    /// Whether, and from where, debug information found nowhere local is
    /// fetched ([`DebugSource::Search`] only).
    pub symbols: Symbols,
    /// Where this install's identity (the key signing its changes) is
    /// kept; `None`: binbun's configuration directory
    /// ([`identity::root`]). An ephemeral session's is made for it and
    /// kept nowhere.
    pub identity: Option<PathBuf>,
    /// The slice of a universal Mach-O file to open, by architecture
    /// (`x86_64`, `arm64e`: [`binbun_loader::Slice::arch`]); `None`: the
    /// slice for this machine's instruction set, else the first
    /// ([`binbun_loader::select`]). [`Session::image`]'s
    /// [`slice`](binbun_loader::Image::slice) says which was opened; its
    /// bytes alone are what the project is keyed by. Other files are
    /// opened whole whatever it says.
    pub arch: Option<String>,
    /// Whether, and with which packs, library functions are named by
    /// their signatures ([`Stage::Signatures`]).
    pub signatures: signatures::Options,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            project: None,
            projects: None,
            autosave: true,
            ephemeral: false,
            style: "kr".to_owned(),
            types: IntSpelling::Fixed,
            declarations: Placement::Scoped,
            names: Naming::Numbered,
            warm: true,
            view: View::Exact,
            debug: DebugSource::Search,
            symbols: Symbols::default(),
            identity: None,
            arch: None,
            signatures: signatures::Options::default(),
        }
    }
}

/// Where a session finds the binary's debug information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DebugSource {
    /// Where the conventions put it
    /// ([`binbun_debuginfo::info::locate::Search::from_environment`]); none if
    /// nothing there is the binary's.
    Search,
    /// In this file: a separate ELF debug file, a PDB, or the binary
    /// itself. If it cannot be read, an [`Event::Failed`] says so and the
    /// analysis goes on without.
    Path(PathBuf),
    /// None: the binary as if it had none.
    Without,
}

/// Wakes a front end's event loop when an event is waiting.
pub type Wake = Arc<dyn Fn() + Send + Sync>;

/// Cancels a session's worker from anywhere (a stop button, an event
/// callback on the worker's own thread): [`Session::cancel`].
#[derive(Clone, Debug)]
pub struct Canceller(Arc<AtomicBool>);

impl Canceller {
    /// Stops the session's worker at its next step.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// One opened binary.
pub struct Session {
    shared: Arc<Shared>,
    requests: Option<Sender<Request>>,
    worker: Option<JoinHandle<()>>,
    /// The verification lane, the interactive one and the call graph's
    /// ([`facts`]).
    lanes: [Option<(Sender<Job>, JoinHandle<()>)>; 3],
    /// The answers kept.
    answers: Arc<Answers>,
    next: AtomicU64,
    view: View,
    /// The synthesised structs as last listed ([`Session::synthesised`]):
    /// the table they were listed from, the user's versions then.
    synthesised: Mutex<Option<SynthesisedCache>>,
    /// The options it was opened with ([`Session::with_debug`]).
    options: Options,
    /// The listing last built, laid over with the overlay it was laid for
    /// ([`Session::listing`]).
    listing: Mutex<Option<Laid>>,
    /// Whether it is a handle a session's own threads write with
    /// ([`Session::handle`]): dropping it cancels nothing.
    handle: bool,
}

/// A listing built under its options, with the overlay whose comments it
/// lays lines for.
struct Laid {
    options: ListingOptions,
    listing: Arc<Listing>,
    overlay: Arc<Overlay>,
}

/// The synthesised structs listed from one table, with the user's
/// versions of them then.
type SynthesisedCache = (Weak<Callers>, Vec<(Typed, String)>, Arc<Vec<Synthesised>>);

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("path", &self.shared.path)
            .field("stage", &self.shared.stage())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Opens the binary at `path`: returns at once, the worker reading,
    /// hashing, parsing and analysing it. Its project's edits are loaded
    /// before [`Stage::Image`] is told; a project that cannot be read, or
    /// is not one (never overwritten then), is reported
    /// ([`Event::Failed`]) and the worker stops.
    ///
    /// # Errors
    ///
    /// The style preset does not exist, or a thread cannot be started.
    pub fn open(path: impl Into<PathBuf>, options: Options) -> Result<Self, Error> {
        let path = path.into();
        let style = Style::preset(&options.style)
            .ok_or_else(|| Error::Project(format!("no style preset {:?}", options.style)))?
            .with_int_spelling(options.types)
            .with_declarations(options.declarations)
            .with_naming(options.names);
        let place = match &options.project {
            _ if options.ephemeral => Place::Ephemeral,
            Some(dir) => Place::Given(dir.clone()),
            None => Place::Central(options.projects.clone()),
        };
        let autosave = options.autosave;
        let journal = Journal::ephemeral().map_err(Error::Project)?;
        Self::start(
            path,
            options,
            style,
            place,
            (Edits::default(), journal),
            autosave,
            None,
        )
    }

    /// A session on the binary at `path` with `options`, its C laid out in
    /// `style`, its project
    /// where `place` says, and `journaled` (a journal and its projection,
    /// until the project's are loaded), saved as made if `autosave`; its
    /// bytes and image `loaded` already, if given (its project is then
    /// known).
    fn start(
        path: PathBuf,
        options: Options,
        style: Style,
        place: Place,
        journaled: (Edits, Journal),
        autosave: bool,
        loaded: Option<Arc<Loaded>>,
    ) -> Result<Self, Error> {
        let shared = Arc::new(Shared::new(
            path,
            place,
            style,
            options.warm,
            journaled,
            autosave,
            DebugInput {
                source: options.debug.clone(),
                symbols: options.symbols.clone(),
                identity: options.identity.clone(),
                arch: options.arch.clone(),
                signatures: options.signatures.clone(),
            },
        ));
        if let Some(loaded) = loaded {
            let _ = shared.loaded.set(loaded);
        }
        let view = options.view;
        let (requests, received) = mpsc::channel();
        let worker = {
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("binbun-session".to_owned())
                .spawn(move || {
                    worker::run(&shared, &received);
                    shared.end();
                })
                .map_err(|error| Error::Project(format!("cannot start the worker: {error}")))?
        };
        let answers = Arc::new(Answers::default());
        let lane = |name: &str| -> Result<(Sender<Job>, JoinHandle<()>), Error> {
            let (jobs, received) = mpsc::channel();
            let shared = Arc::clone(&shared);
            let answers = Arc::clone(&answers);
            let thread = thread::Builder::new()
                .name(name.to_owned())
                .spawn(move || facts::lane(&shared, &answers, &received))
                .map_err(|error| Error::Project(format!("cannot start {name}: {error}")))?;
            Ok((jobs, thread))
        };
        let lanes = [
            Some(lane("binbun-verify")?),
            Some(lane("binbun-facts")?),
            Some(lane("binbun-calls")?),
        ];
        Ok(Self {
            shared,
            requests: Some(requests),
            worker: Some(worker),
            lanes,
            answers,
            next: AtomicU64::new(0),
            view,
            synthesised: Mutex::new(None),
            options,
            listing: Mutex::new(None),
            handle: false,
        })
    }

    /// A handle on the session `shared` is, for its own threads to write
    /// edits with (the signatures' runs): no worker or lanes of its own,
    /// and dropping it cancels nothing.
    pub(crate) fn handle(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            requests: None,
            worker: None,
            lanes: [None, None, None],
            answers: Arc::new(Answers::default()),
            next: AtomicU64::new(0),
            view: View::Exact,
            synthesised: Mutex::new(None),
            options: Options::default(),
            listing: Mutex::new(None),
            handle: true,
        }
    }

    /// The binary's path.
    pub fn path(&self) -> &Path {
        &self.shared.path
    }

    /// The binary's project, once the image is parsed ([`Stage::Image`]):
    /// where [`Options::project`] says, else its own in binbun's data
    /// directory ([`project`]).
    pub fn project(&self) -> Option<&Project> {
        self.shared
            .project
            .get()
            .and_then(|resolved| resolved.project.as_ref())
    }

    /// The binary's key (its SHA-256 and file name), once the image is
    /// parsed; none with a project given ([`Options::project`]).
    pub fn key(&self) -> Option<&Key> {
        self.shared
            .project
            .get()
            .and_then(|resolved| resolved.key.as_ref())
    }

    /// The origin of chain `chain` ([`journal::ChainOrigin`]), as its first
    /// change taken carries it: what shows a store, which opens nothing,
    /// whose the chain is.
    pub fn chain_origin(&self, chain: journal::ChainId) -> Option<journal::ChainOrigin> {
        self.shared.state().journal.chain_origin(chain)
    }

    /// The stage reached.
    pub fn stage(&self) -> Stage {
        self.shared.stage()
    }

    /// The functions done and the total of the whole-program pass the
    /// stage after [`Self::stage`] is running (the references, a pass of
    /// finding what callers read: [`Database::progress`]); `None` before
    /// the functions are recovered.
    pub fn progress(&self) -> Option<(usize, usize)> {
        self.database()?.progress().get()
    }

    /// Waits until `stage` is reached, up to `timeout` (`None`: as long as
    /// it takes), or the worker stops first (opening failed, or the
    /// session was cancelled). Without warming ([`Options::warm`]),
    /// [`Stage::Callers`] is as far as it goes: waiting for
    /// [`Stage::Warmed`] waits for it.
    pub fn wait(&self, stage: Stage, timeout: Option<Duration>) -> Waited {
        self.shared.wait(stage, timeout)
    }

    /// How far the session's state has come: the analyses before this
    /// one and the edits made.
    pub fn revision(&self) -> Revision {
        Revision {
            analysis: self.shared.analysis.load(Ordering::Relaxed),
            edits: self.shared.state().changes,
        }
    }

    /// The user's names, comments, bookmarks, numbers' forms and frame
    /// slots' names as the listing shows them ([`Overlay::of`] the edits
    /// now), with the enumerations the forms name once the image's types
    /// are read.
    pub fn overlay(&self) -> Arc<Overlay> {
        let database = self.database();
        let mut state = self.shared.state();
        if let Some(overlay) = &state.overlay {
            return Arc::clone(overlay);
        }
        let mut overlay = Overlay::of(&state.edits);
        let enums = overlay
            .numbers
            .values()
            .any(|form| matches!(form, NumberForm::Enum(_)));
        if let Some(database) = database {
            overlay.enums = types::enumerations(database, &state.edits);
        }
        let overlay = Arc::new(overlay);
        // Without the types, enumerations are read again later.
        if database.is_some() || !enums {
            state.overlay = Some(Arc::clone(&overlay));
        }
        overlay
    }

    /// The listing of the image under `options`, with a line laid under
    /// each comment for each of its lines after the first
    /// ([`Listing::set_comments`], the comments now); built on the calling
    /// thread the first time (its cross-references built first if they
    /// are not yet), then kept until other options are asked for. `None`
    /// before the functions are recovered.
    pub fn listing(&self, options: &ListingOptions) -> Option<Arc<Listing>> {
        let database = self.database()?;
        let overlay = self.overlay();
        let mut kept = self.listing.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(laid) = kept.as_mut()
            && laid.options == *options
        {
            if !Arc::ptr_eq(&laid.overlay, &overlay) && laid.overlay.comments != overlay.comments {
                Arc::make_mut(&mut laid.listing).set_comments(&overlay.comments);
            }
            laid.overlay = overlay;
            return Some(Arc::clone(&laid.listing));
        }
        let mut listing = Listing::build(database, options);
        listing.set_comments(&overlay.comments);
        let listing = Arc::new(listing);
        *kept = Some(Laid {
            options: options.clone(),
            listing: Arc::clone(&listing),
            overlay,
        });
        Some(listing)
    }

    /// The image, once parsed ([`Stage::Image`]).
    pub fn image(&self) -> Option<&Image<'_>> {
        self.shared
            .loaded
            .get()
            .map(|loaded| loaded.borrow_dependent())
    }

    /// The file's bytes, once the image is parsed ([`Stage::Image`]).
    pub fn bytes(&self) -> Option<&[u8]> {
        self.shared
            .loaded
            .get()
            .map(|loaded| loaded.borrow_owner().as_slice())
    }

    /// The architecture of the slice of a universal Mach-O file opened
    /// (`x86_64`, `arm64e`: [`binbun_loader::Slice::arch`]), once the
    /// image is parsed; `None` for any other file.
    pub fn slice(&self) -> Option<&str> {
        self.image()?
            .slice
            .as_ref()
            .map(|slice| slice.arch.as_str())
    }

    /// The whole file's SHA-256, once the image is parsed: the key's
    /// ([`Self::key`]), unless the image is one slice of a universal file
    /// (whose key is the slice's), then the file's bytes hashed.
    pub fn file_sha256(&self) -> Option<[u8; 32]> {
        match (self.key(), self.slice()) {
            (Some(key), None) => Some(*key.sha256()),
            _ => Some(*Key::new(self.bytes()?, "").sha256()),
        }
    }

    /// The database, once the functions are recovered
    /// ([`Stage::Analysed`]). Its whole-program queries
    /// ([`Database::references`], [`Database::callers`]) are computed by
    /// the worker; asked for before their stage, they are computed (or
    /// waited for) on the calling thread.
    pub fn database(&self) -> Option<&Database<'_>> {
        self.shared.database()
    }

    /// The file the debug information was read from, once the functions
    /// are recovered ([`Stage::Analysed`]); `None` without debug
    /// information.
    pub fn debug_file(&self) -> Option<&Path> {
        self.shared.debug_file.get().map(PathBuf::as_path)
    }

    /// What became of the binary's debug information on a symbol server,
    /// if anything ([`Options::symbols`]): `None` until the image is
    /// parsed, and when debug information was found locally, none is
    /// needed from a server, or fetching is never allowed.
    pub fn symbols(&self) -> Option<SymbolState> {
        symbols::state(&self.shared)
    }

    /// Fetches the debug information offered
    /// ([`SymbolState::Available`], or again after
    /// [`SymbolState::Failed`]) on a thread of its own, telling
    /// [`Event::Symbols`] as it goes; whether it started. This tells the
    /// server which binary is analysed: only on the user's word.
    pub fn fetch_symbols(&self) -> bool {
        symbols::fetch(&self.shared)
    }

    /// The binary opened anew with the debug information at `file` (a
    /// fetched one: [`SymbolState::Fetched`]), with this session's options
    /// and its edits as they are now, decompiled again from the start.
    ///
    /// # Errors
    ///
    /// As [`Session::open`]: a thread cannot be started.
    pub fn with_debug(&self, file: impl Into<PathBuf>) -> Result<Self, Error> {
        let (journaled, autosave) = self.journaled();
        let place = match self.shared.project.get() {
            Some(resolved) => Place::Known(resolved.clone()),
            None => self.shared.place.clone(),
        };
        Self::start(
            self.shared.path.clone(),
            Options {
                debug: DebugSource::Path(file.into()),
                ..self.options.clone()
            },
            self.style(),
            place,
            journaled,
            autosave,
            None,
        )
        .map(|session| self.succeeded_by(session))
    }

    /// The journal and its projection as they are now, and whether they
    /// are saved as made.
    fn journaled(&self) -> ((Edits, Journal), bool) {
        let state = self.shared.state();
        ((state.edits.clone(), state.journal.clone()), state.autosave)
    }

    /// Takes `from`'s edits (its journal: its history, undo and redo, the
    /// group open) as they are now in place of this session's: a session
    /// opened again with debug information
    /// ([`Session::with_debug`]) taking the place of the one shown keeps
    /// the edits made there while it was being analysed. Every function
    /// decompiled is decompiled again with them and the whole listing
    /// changes; what changed (told as [`Event::Changed`], then
    /// [`Event::Bookmarks`]: the journal's others' and private bookmarks
    /// come with it).
    pub fn take_edits(&self, from: &Self) -> Arc<Change> {
        let ((edits, journal), _) = from.journaled();
        let (changes, group) = {
            let state = from.shared.state();
            (state.changes, state.group.clone())
        };
        let mut change = self.redefined();
        {
            let mut state = self.shared.state();
            state.edits = edits.clone();
            state.journal = journal;
            state.group = group;
            state.changes = changes;
            state.generation += 1;
            state.overlay = None;
            let printed: Vec<worker::Key> = state.documents.keys().copied().collect();
            state.stale.extend(printed);
            // What no longer is an edit no longer fails to resolve.
            self.shared
                .unresolved()
                .retain(|unresolved| edits.all().any(|edit| edit == unresolved.edit));
        }
        if let Some(database) = self.database() {
            change.listing = worker::whole(database);
            let (user, unresolved) = types::user_types(database, &edits);
            database.set_user(user);
            let mut state = self.shared.state();
            state.retyped += 1;
            for &function in &change.documents {
                for view in [View::Exact, View::Reading] {
                    state.decompiled.remove(&(function, worker::slot(view)));
                }
            }
            drop(state);
            self.shared
                .found_unresolved(worker::resolve(database, &edits));
            self.shared.found_unresolved(unresolved);
        }
        let change = Arc::new(change);
        self.shared.emit(&Event::Changed(Arc::clone(&change)));
        self.shared.emit(&Event::Bookmarks);
        change
    }

    /// The style the C is laid out in now: the preset opened with
    /// ([`Options::style`]) and the options set since ([`Self::set_style`]).
    pub fn style(&self) -> Style {
        self.shared.style()
    }

    /// Lays the C out in `style` from now on (its layout, how it spells
    /// integer types, where it declares locals, any of its options): every
    /// document printed is printed again when next asked for (none
    /// decompiled again: the functions keep where their passes placed
    /// each local), and
    /// they are what changed (told as [`Event::Changed`], as an edit's);
    /// nothing when `style` is the style already. A session opened again
    /// from this one ([`Self::with_debug`], [`Self::reanalysed`]) keeps
    /// it.
    pub fn set_style(&self, style: Style) -> Arc<Change> {
        if self.shared.style() == style {
            return Arc::new(Change::default());
        }
        self.shared.set_style(style);
        let documents = {
            let mut state = self.shared.state();
            // A document being printed under the old style is printed again.
            state.generation += 1;
            let printed: Vec<worker::Key> = state.documents.keys().copied().collect();
            state.stale.extend(printed.iter().copied());
            let mut documents: Vec<FunctionId> =
                printed.into_iter().map(|(function, _)| function).collect();
            documents.dedup();
            documents
        };
        // Synthesised structs and global declarations are C in the style.
        *self
            .synthesised
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        let change = Arc::new(Change {
            documents,
            listing: Vec::new(),
        });
        self.shared.emit(&Event::Changed(Arc::clone(&change)));
        change
    }

    /// The user's corrections of recovery ([`Edits::corrections`]).
    pub fn corrections(&self) -> Corrections {
        self.shared.state().edits.corrections().clone()
    }

    /// Whether the functions were recovered with the corrections the edits
    /// hold now (`None` before they are recovered): else a session opened
    /// [`Self::reanalysed`] recovers with them.
    pub fn recovered_as_corrected(&self) -> Option<bool> {
        let database = self.database()?;
        Some(database.corrections() == self.shared.state().edits.corrections())
    }

    /// Takes `corrections` as the user's corrections of recovery, each one
    /// not among them now checked first against the program as recovered
    /// ([`Database::check_item`], [`Database::check_bounds`]); saved as
    /// an edit is. Nothing is recovered again here: a session opened
    /// [`Self::reanalysed`] recovers with them.
    ///
    /// # Errors
    ///
    /// A correction cannot apply ([`Error::Correction`], the reason);
    /// nothing is changed. The change cannot be made, or the share does
    /// not take it ([`Error::Refused`]).
    pub fn set_corrections(&self, corrections: &Corrections) -> Result<Arc<Change>, Error> {
        let before = self.corrections();
        if let Some(database) = self.database() {
            for (&address, &item) in corrections.items() {
                if before.item(address) != Some(item) {
                    database
                        .check_item(address, item)
                        .map_err(Error::Correction)?;
                }
            }
            for (&entry, &bounds) in corrections.functions() {
                if before.bounds(entry) != Some(bounds) {
                    database
                        .check_bounds(entry, bounds)
                        .map_err(Error::Correction)?;
                }
            }
        }
        // Each item and function's bounds a key of its own.
        let mut ops = Vec::new();
        let items = |c: &Corrections| c.items().keys().copied().collect::<BTreeSet<u64>>();
        for address in items(&before).union(&items(corrections)) {
            let item = corrections.item(*address);
            if before.item(*address) != item {
                ops.push((JournalKey::Item(*address), Value::Item(item)));
            }
        }
        let functions = |c: &Corrections| c.functions().keys().copied().collect::<BTreeSet<u64>>();
        for entry in functions(&before).union(&functions(corrections)) {
            let bounds = corrections.bounds(*entry);
            if before.bounds(*entry) != bounds {
                ops.push((JournalKey::Bounds(*entry), Value::Bounds(bounds)));
            }
        }
        if ops.is_empty() {
            return Ok(Arc::new(Change::default()));
        }
        self.write("Correct recovery", ops, Change::default(), false)
    }

    /// The binary opened anew with this session's options, project and
    /// debug information file, and its edits as they are now, their
    /// corrections taken by recovery ([`Database::with_corrections`]); its
    /// bytes and image are this one's (not read or parsed again), once
    /// parsed. As with [`Self::with_debug`], it takes this one's place
    /// once its functions are recovered, with [`Self::take_edits`].
    ///
    /// # Errors
    ///
    /// As [`Session::open`]: a thread cannot be started.
    pub fn reanalysed(&self) -> Result<Self, Error> {
        let (journaled, autosave) = self.journaled();
        let loaded = self.shared.loaded.get().cloned();
        let place = match self.shared.project.get() {
            Some(resolved) => Place::Known(resolved.clone()),
            None => self.shared.place.clone(),
        };
        let debug = match self.debug_file() {
            Some(file) => DebugSource::Path(file.to_owned()),
            None => self.options.debug.clone(),
        };
        let session = Self::start(
            self.shared.path.clone(),
            Options {
                debug,
                ..self.options.clone()
            },
            self.style(),
            place,
            journaled,
            autosave,
            loaded,
        )?;
        Ok(self.succeeded_by(session))
    }

    /// `next`, opened again from this session, counting one analysis more
    /// and this one's edits ([`Self::revision`]).
    fn succeeded_by(&self, next: Self) -> Self {
        // The project stays held, by the session that follows this one.
        next.shared.follow(self.shared.held());
        let Revision { analysis, edits } = self.revision();
        next.shared.analysis.store(analysis + 1, Ordering::Relaxed);
        next.shared.state().changes = edits;
        next
    }

    /// The compilation unit the debug information states the function at
    /// `entry` is defined in.
    pub fn source_unit(&self, entry: u64) -> Option<&Unit> {
        self.database()?.debug()?.model().unit_of(entry)
    }

    /// Every event from now on, on a channel, `wake` called after each is
    /// sent; the first is the stage reached, then the symbol server state,
    /// the failure told last and the edits found not to resolve so far
    /// ([`Self::unresolved`]), if any. Dropping the receiver unsubscribes.
    pub fn subscribe(&self, wake: Option<Wake>) -> Receiver<Event> {
        let (sender, receiver) = mpsc::channel();
        self.shared.subscribe(Arc::new(move |event: &Event| {
            let listening = sender.send(event.clone()).is_ok();
            if listening && let Some(wake) = &wake {
                wake();
            }
            listening
        }));
        receiver
    }

    /// Calls `callback` with every event from now on, on the thread making
    /// it (the worker's, or the one making an edit); the first is the
    /// stage reached, on this thread. It must neither block nor call the
    /// session (but a [`Canceller`]): it runs where events are made.
    pub fn on_event(&self, callback: impl Fn(&Event) + Send + Sync + 'static) {
        self.shared.subscribe(Arc::new(move |event: &Event| {
            callback(event);
            true
        }));
    }

    /// Asks for function `function`'s document; the request's number, which
    /// the [`Event::Document`] answering it carries.
    pub fn request(&self, function: FunctionId) -> u64 {
        self.request_view(function, self.view)
    }

    /// Asks for function `function`'s document in `view`; the request's
    /// number, which the [`Event::Document`] answering it carries. Each
    /// view of a function is decompiled once and kept.
    pub fn request_view(&self, function: FunctionId, view: View) -> u64 {
        let request = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let sent = self.send(Request::Document {
            function,
            view,
            reply: Reply::Event(request),
        });
        if !sent {
            self.shared.emit(&Event::Document {
                request,
                function,
                result: Err(STOPPED.to_owned()),
            });
        }
        request
    }

    /// Function `function`'s document, waiting for it (behind the requests
    /// before it, and the analysis up to [`Stage::Callers`]).
    ///
    /// # Errors
    ///
    /// The function does not decompile or print (as `binbun decompile`
    /// says), or the worker stopped.
    pub fn document(&self, function: FunctionId) -> Result<Arc<Document>, String> {
        self.document_view(function, self.view)
    }

    /// Function `function`'s document in `view`, waiting for it (as
    /// [`Session::document`]).
    ///
    /// # Errors
    ///
    /// The function does not decompile or print in `view`, or the worker
    /// stopped.
    pub fn document_view(&self, function: FunctionId, view: View) -> Result<Arc<Document>, String> {
        let (reply, answer) = mpsc::channel();
        if !self.send(Request::Document {
            function,
            view,
            reply: Reply::Channel(reply),
        }) {
            return Err(STOPPED.to_owned());
        }
        answer.recv().unwrap_or_else(|_| Err(STOPPED.to_owned()))
    }

    /// Function `function`'s document in `view`, made on the calling
    /// thread (decompiled first if it is not yet; kept, as the worker
    /// keeps it): for a pass through every function on threads of its own
    /// (a search) that never holds up the worker's requests.
    ///
    /// # Errors
    ///
    /// The functions are not recovered yet, or the function does not
    /// decompile or print in `view`.
    pub fn document_here(&self, function: FunctionId, view: View) -> Result<Arc<Document>, String> {
        let database = self
            .database()
            .ok_or_else(|| Error::NotAnalysed.to_string())?;
        worker::document(&self.shared, database, function, view)
    }

    /// Asks `question` of function `function` in `view`; what cancels it.
    /// The [`Event::Answer`] with its number answers it: at once, on this
    /// thread, if the answer is kept ([`Session::answer`]); else from a
    /// lane once the functions are recovered (asked before, it is never
    /// answered). Verification has a lane of its own, the call graph's
    /// questions another; the other questions share one, in order.
    pub fn ask(&self, function: FunctionId, view: View, question: Question) -> Asked {
        let request = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let kept = self.answers.get(function, view, &question);
        let lane = question.lane();
        let (job, asked) = facts::job(request, function, view, question);
        if let Some(answer) = kept {
            job.answer(answer.clone());
            self.shared.emit(&Event::Answer {
                request,
                function,
                view,
                answer,
            });
        } else if let Some(Some((jobs, _))) = self.lanes.get(lane) {
            let _ = jobs.send(job);
        }
        asked
    }

    /// The answer kept to `question` of function `function` in `view`, if
    /// it was asked and answered.
    pub fn answer(&self, function: FunctionId, view: View, question: &Question) -> Option<Answer> {
        self.answers.get(function, view, question)
    }

    /// The user's edits.
    pub fn edits(&self) -> Edits {
        self.shared.state().edits.clone()
    }

    /// The edits found not to resolve so far: functions', globals' and
    /// comments' once the functions are recovered, variables' once their
    /// function is printed.
    pub fn unresolved(&self) -> Vec<Unresolved> {
        self.shared.unresolved().iter().cloned().collect()
    }

    /// The name of `address`: the user's, else the database's
    /// ([`Database::data_name`]).
    pub fn name(&self, address: u64) -> Option<String> {
        let user = self.shared.state().edits.name(address).map(str::to_owned);
        user.or_else(|| self.database()?.data_name(address))
    }

    /// Names the function at `entry` `name` (`None` or empty: its own name
    /// again); what changed.
    ///
    /// # Errors
    ///
    /// The functions are recovered and none starts at `entry`; the change
    /// cannot be made, or the share does not take it ([`Error::Refused`]).
    pub fn rename_function(&self, entry: u64, name: Option<&str>) -> Result<Arc<Change>, Error> {
        if let Some(database) = self.database()
            && database.function_at(entry).is_none()
        {
            return Err(Error::NoFunction(entry));
        }
        let name = given(name);
        let change = self.printing(entry);
        self.write(
            "Rename function",
            vec![(JournalKey::FunctionName(entry), Value::Text(name))],
            change,
            false,
        )
    }

    /// Names the global at `address` `name` (`None` or empty: its own name
    /// again); what changed.
    ///
    /// # Errors
    ///
    /// The change cannot be made, or the share does not take it
    /// ([`Error::Refused`]).
    pub fn rename_global(&self, address: u64, name: Option<&str>) -> Result<Arc<Change>, Error> {
        let name = given(name);
        let change = self.printing(address);
        self.write(
            "Rename global",
            vec![(JournalKey::GlobalName(address), Value::Text(name))],
            change,
            false,
        )
    }

    /// Names variable `var` of function `function` (as its document
    /// shows it) `name` (`None` or empty: the printer's name again); what
    /// changed: that document.
    ///
    /// # Errors
    ///
    /// The function is not decompiled (or does not decompile), or has no
    /// such variable; the change cannot be made, or the share does not
    /// take it ([`Error::Refused`]).
    pub fn rename_variable(
        &self,
        function: FunctionId,
        var: VarId,
        name: Option<&str>,
    ) -> Result<Arc<Change>, Error> {
        self.rename_variable_in(function, self.view, var, name)
    }

    /// Names variable `var` of function `function` as its document in
    /// `view` shows it `name` (as [`Session::rename_variable`]): the name
    /// goes to what the variable was made from, so both views print it. A
    /// global is named as such ([`Session::rename_global`], or
    /// [`Session::rename_function`] when a function starts there): one name
    /// wherever it is used, the listing's and every C's; a name the
    /// function's C alone gave it goes in the same change.
    ///
    /// # Errors
    ///
    /// The function is not decompiled in `view` (or does not decompile),
    /// or has no such variable; the change cannot be made, or the share
    /// does not take it ([`Error::Refused`]).
    pub fn rename_variable_in(
        &self,
        function: FunctionId,
        view: View,
        var: VarId,
        name: Option<&str>,
    ) -> Result<Arc<Change>, Error> {
        let database = self.database().ok_or(Error::NotAnalysed)?;
        let declarations = database.declarations().ok_or(Error::NotAnalysed)?;
        let decompiled = self
            .shared
            .state()
            .decompiled
            .get(&(function, worker::slot(view)))
            .and_then(|decompiled| decompiled.clone().ok())
            .ok_or(Error::NotDecompiled(function))?;
        let variable =
            Variable::of(&decompiled.l2, var, declarations).ok_or(Error::NoVariable(var))?;
        let name = given(name);
        if let Some(VarKind::Global(address)) = decompiled.l2.var(var).map(|v| v.kind) {
            return self.rename_global_variable(function, address, variable, name);
        }
        // A frame variable's name is its slot's in the listing too.
        let listing = if variable.slot().is_some() {
            self.code(function)
        } else {
            Vec::new()
        };
        self.write(
            "Rename variable",
            vec![(JournalKey::VariableName(variable), Value::Text(name))],
            Change {
                documents: vec![function],
                listing,
            },
            false,
        )
    }

    /// Names the global at `address`, variable `variable` of function
    /// `function`'s C, `name` ([`Session::rename_variable_in`]); what
    /// changed: what prints the global, and the function.
    ///
    /// # Errors
    ///
    /// The change cannot be made, or the share does not take it
    /// ([`Error::Refused`]).
    fn rename_global_variable(
        &self,
        function: FunctionId,
        address: u64,
        variable: Variable,
        name: Option<String>,
    ) -> Result<Arc<Change>, Error> {
        let at_function = self
            .database()
            .is_some_and(|database| database.function_at(address).is_some());
        let (label, key) = if at_function {
            ("Rename function", JournalKey::FunctionName(address))
        } else {
            ("Rename global", JournalKey::GlobalName(address))
        };
        let mut ops = vec![(key, Value::Text(name))];
        if self.shared.state().edits.variable(&variable).is_some() {
            ops.push((JournalKey::VariableName(variable), Value::Text(None)));
        }
        let mut change = self.printing(address);
        if let Err(at) = change.documents.binary_search(&function) {
            change.documents.insert(at, function);
        }
        self.write(label, ops, change, false)
    }

    /// The variable of function `function`'s exact C that is exactly the
    /// frame slot at `offset` (from the stack pointer on entry): the one
    /// variable the C prints made from that slot and from no other, if one
    /// is (renaming the slot is renaming it; a variable the C does not
    /// print is none of its). Prints the function if it is not yet.
    ///
    /// # Errors
    ///
    /// The functions are not recovered yet, or it does not decompile.
    pub fn slot_variable(&self, function: FunctionId, offset: i64) -> Result<Option<VarId>, Error> {
        let database = self.database().ok_or(Error::NotAnalysed)?;
        let document = worker::document(&self.shared, database, function, View::Exact)
            .map_err(|_| Error::NotDecompiled(function))?;
        let printed: BTreeSet<VarId> = document
            .spans
            .iter()
            .filter_map(|span| {
                if let Some(Node::Var(var)) = span.node {
                    Some(var)
                } else {
                    None
                }
            })
            .collect();
        Ok(slot_variable(&document.decompiled.l2, &printed, offset))
    }

    /// Names the frame slot at `offset` (from the stack pointer on entry)
    /// of the function at `entry` `name` as a slot (`None` or empty: the
    /// listing's name again), for a slot no variable of the C is exactly
    /// ([`Session::slot_variable`]); what changed: the function's listing
    /// lines.
    ///
    /// # Errors
    ///
    /// The change cannot be made, or the share does not take it
    /// ([`Error::Refused`]).
    pub fn rename_slot(
        &self,
        entry: u64,
        offset: i64,
        name: Option<&str>,
    ) -> Result<Arc<Change>, Error> {
        let name = given(name);
        let listing = self
            .database()
            .and_then(|database| database.function_at(entry))
            .map(|function| self.code(function))
            .unwrap_or_default();
        self.write(
            "Rename frame slot",
            vec![(JournalKey::Slot(entry, offset), Value::Text(name))],
            Change {
                documents: Vec::new(),
                listing,
            },
            false,
        )
    }

    /// The code of function `function`: its blocks' addresses, merged.
    fn code(&self, function: FunctionId) -> Vec<Range<u64>> {
        let Some(database) = self.database() else {
            return Vec::new();
        };
        let program = database.program();
        let blocks = database
            .function(function)
            .map(|f| {
                f.blocks
                    .iter()
                    .filter_map(|&block| program.blocks.get(block))
                    .map(|block| block.start..block.end)
                    .collect()
            })
            .unwrap_or_default();
        worker::merge(blocks)
    }

    /// Comments `address` with `text` (`None` or empty: no comment; lines
    /// apart by `\n`); what changed: its listing line and the documents of
    /// the functions holding the instruction there (their C prints the
    /// comment: [`Document::comments`]). Presentation only: nothing is
    /// decompiled again.
    ///
    /// # Errors
    ///
    /// The change cannot be made, or the share does not take it
    /// ([`Error::Refused`]).
    pub fn comment(&self, address: u64, text: Option<&str>) -> Result<Arc<Change>, Error> {
        let text = given(text);
        let line = address..address.saturating_add(1);
        self.write(
            "Comment",
            vec![(JournalKey::Comment(address), Value::Text(text))],
            Change {
                documents: self.holding(address),
                listing: vec![line],
            },
            false,
        )
    }

    /// Bookmarks `address` as `name` (the GUI's `Alt+M`; `None` or empty: no
    /// bookmark): the bookmark there of whoever makes the change (this
    /// author, or the agent of the group open: each author's bookmarks
    /// are their own); what changed: its listing line (its mark).
    ///
    /// # Errors
    ///
    /// The change cannot be made, or the share does not take it
    /// ([`Error::Refused`]).
    pub fn bookmark(&self, address: u64, name: Option<&str>) -> Result<Arc<Change>, Error> {
        let name = given(name);
        let line = address..address.saturating_add(1);
        let author = self.shared.state().journal.writing_as();
        self.write(
            "Bookmark",
            vec![(JournalKey::Bookmark(author, address), Value::Text(name))],
            Change {
                documents: Vec::new(),
                listing: vec![line],
            },
            false,
        )
    }

    /// Writes the number `value` the instruction at `address` uses in
    /// `form` (`None`: as the listing and the printer choose), in place of
    /// its form at another width ([`Edits::set_number`]); what
    /// changed: its listing line and the documents of the functions
    /// holding the instruction (their C prints it so). Presentation only:
    /// nothing is decompiled again.
    ///
    /// # Errors
    ///
    /// The change cannot be made, or the share does not take it
    /// ([`Error::Refused`]).
    pub fn number(
        &self,
        address: u64,
        value: u64,
        form: Option<NumberForm>,
    ) -> Result<Arc<Change>, Error> {
        let line = address..address.saturating_add(1);
        let documents = self.holding(address);
        self.write(
            "Number form",
            vec![(
                JournalKey::Number(address, number::canonical(value)),
                Value::Number(form.map(|form| Stated { value, form })),
            )],
            Change {
                documents,
                listing: vec![line],
            },
            false,
        )
    }

    /// The functions with a block holding the instruction at `address`, in
    /// order (none before the functions are recovered).
    fn holding(&self, address: u64) -> Vec<FunctionId> {
        self.database()
            .and_then(|database| {
                let block = database.program().block_containing(address)?;
                Some(
                    database
                        .functions()
                        .filter(|(_, function)| function.blocks.contains(&block))
                        .map(|(id, _)| id)
                        .collect(),
                )
            })
            .unwrap_or_default()
    }

    /// The identity of variable `var` of function `function` as its
    /// document in `view` shows it: what renames and types attach to.
    ///
    /// # Errors
    ///
    /// The function is not decompiled in `view` (or does not decompile),
    /// or has no such variable.
    pub fn variable(
        &self,
        function: FunctionId,
        view: View,
        var: VarId,
    ) -> Result<Variable, Error> {
        let database = self.database().ok_or(Error::NotAnalysed)?;
        let declarations = database.declarations().ok_or(Error::NotAnalysed)?;
        let decompiled = self
            .shared
            .state()
            .decompiled
            .get(&(function, worker::slot(view)))
            .and_then(|decompiled| decompiled.clone().ok())
            .ok_or(Error::NotDecompiled(function))?;
        Variable::of(&decompiled.l2, var, declarations).ok_or(Error::NoVariable(var))
    }

    /// The user's type of `typed`, as C.
    pub fn type_of(&self, typed: &Typed) -> Option<String> {
        self.shared.state().edits.type_of(typed).map(str::to_owned)
    }

    /// The names a type may be written with (C's, the type library's, the
    /// user's definitions), sorted: what completes a type typed.
    pub fn type_names(&self) -> Vec<String> {
        let Some(database) = self.database() else {
            return Vec::new();
        };
        let edits = self.shared.state().edits.clone();
        types::scope(database, &edits).0.names()
    }

    /// Whether C `c` can type `typed` (as [`Session::set_type`] would
    /// take it), without taking it. A variable's type must be as wide as
    /// the variable decompiled (decompilation takes no other: a register
    /// holds its values' width, a frame slot its bytes).
    ///
    /// # Errors
    ///
    /// Why not, with the bytes of `c` at fault; [`Error::NotAnalysed`]
    /// before the functions are recovered.
    pub fn check_type(&self, typed: &Typed, c: &str) -> Result<(), Error> {
        let database = self.database().ok_or(Error::NotAnalysed)?;
        let edits = self.shared.state().edits.clone();
        let (mut scope, _) = types::scope(database, &edits);
        let width = match typed {
            Typed::Variable(variable) => self.width(variable),
            Typed::Prototype(_) | Typed::Global(_) | Typed::Struct { .. } => None,
        };
        types::read(&mut scope, typed, c, width)
            .map(|_| ())
            .map_err(Error::Type)
    }

    /// The width in bits of `variable` as its function is decompiled (in
    /// either view), if it is.
    fn width(&self, variable: &Variable) -> Option<u64> {
        let declarations = self.database()?.declarations()?;
        let state = self.shared.state();
        state.decompiled.values().find_map(|decompiled| {
            let l2 = &decompiled.as_ref().ok()?.l2;
            if l2.address != variable.function {
                return None;
            }
            let var = variable.resolve(l2, declarations).ok()?;
            let ty = l2.variables.get(usize::try_from(var.0).ok()?)?.ty;
            l2.types.width(ty)
        })
    }

    /// Types `typed` as C `c` states (`None` or empty: as analysis types
    /// it again): the strongest evidence, above debug information. What
    /// changed: the documents it reaches, decompiled again (a variable's
    /// function; a prototype's or a global's function and the functions
    /// referring to it).
    ///
    /// # Errors
    ///
    /// The C is refused ([`Session::check_type`]); nothing is changed. The
    /// change cannot be made, or the share does not take it
    /// ([`Error::Refused`]).
    pub fn set_type(&self, typed: Typed, c: Option<&str>) -> Result<Arc<Change>, Error> {
        let c = given(c);
        if let Some(c) = &c
            && self.database().is_some()
        {
            self.check_type(&typed, c)?;
        }
        let change = self.reached(slice::from_ref(&typed));
        self.write(
            "Set type",
            vec![(JournalKey::Type(typed), Value::Text(c))],
            change,
            true,
        )
    }

    /// Defines the struct, union, enumeration or typedef C `c` defines
    /// (the last, if several), as the user's: it replaces a definition of
    /// the same key (the type library's, a synthesised struct's name, the
    /// user's before) wherever the engine uses it: the type library's
    /// declarations that name it (prototypes, fields, globals), the
    /// struct table's names, the definitions the C prints. The key
    /// defined and what changed: every function decompiled (any may
    /// print or use the type) and every document a user's type reaches.
    ///
    /// # Errors
    ///
    /// The C is refused or defines nothing; nothing is changed. The change
    /// cannot be made, or the share does not take it ([`Error::Refused`]).
    pub fn define(&self, c: &str) -> Result<(String, Arc<Change>), Error> {
        let database = self.database().ok_or(Error::NotAnalysed)?;
        let edits = self.shared.state().edits.clone();
        let (mut scope, _) = types::scope(database, &edits);
        let defined = scope.define(c).map_err(Error::Type)?;
        let key = defined.last().cloned().ok_or_else(|| {
            Error::Type(CError {
                message: "nothing is defined".to_owned(),
                span: 0..c.len(),
            })
        })?;
        let change = self.redefined();
        let c = c.trim().to_owned();
        let change = self.write(
            "Define type",
            vec![(JournalKey::Definition(key.clone()), Value::Text(Some(c)))],
            change,
            true,
        )?;
        Ok((key, change))
    }

    /// The layout of the struct or union C `c` defines, with the user's
    /// other definitions and the type library's types in scope; nothing
    /// is defined.
    ///
    /// # Errors
    ///
    /// The C is refused ([`Error::Type`]), or the functions are not
    /// recovered yet.
    pub fn struct_layout(&self, c: &str) -> Result<StructLayout, Error> {
        let database = self.database().ok_or(Error::NotAnalysed)?;
        let edits = self.shared.state().edits.clone();
        let (mut scope, _) = types::scope(database, &edits);
        types::struct_layout(&mut scope, c).map_err(Error::Type)
    }

    /// The layout of the struct, union or enumeration C `c` defines, with
    /// the user's other definitions and the type library's types in
    /// scope; nothing is defined.
    ///
    /// # Errors
    ///
    /// The C is refused ([`Error::Type`]), or the functions are not
    /// recovered yet.
    pub fn type_layout(&self, c: &str) -> Result<TypeLayout, Error> {
        let database = self.database().ok_or(Error::NotAnalysed)?;
        let edits = self.shared.state().edits.clone();
        let (mut scope, _) = types::scope(database, &edits);
        types::type_layout(&mut scope, c).map_err(Error::Type)
    }

    /// Every enumeration of the type library and the user's definitions,
    /// by the name a number's form names it with ([`NumberForm::Enum`]):
    /// a typedef naming it, else its `enum tag`; sorted by it. None while
    /// the functions are not recovered.
    pub fn enumerations(&self) -> Vec<(String, Enumeration)> {
        let Some(database) = self.database() else {
            return Vec::new();
        };
        let edits = self.shared.state().edits.clone();
        types::all_enumerations(database, &edits)
    }

    /// The enumeration type name `name` names (a typedef's, `enum tag`),
    /// through typedefs, in the type library and the user's definitions.
    pub fn enumeration(&self, name: &str) -> Option<Enumeration> {
        let edits = self.shared.state().edits.clone();
        let (mut scope, _) = types::scope(self.database()?, &edits);
        types::enumeration(&mut scope, name)
    }

    /// The definition as C of the struct, union or enumeration `key`
    /// names: the user's, else the type library's, if either defines it.
    pub fn definition_text(&self, key: &str) -> Option<String> {
        let edits = self.shared.state().edits.clone();
        if let Some(c) = edits.definitions().get(key) {
            return Some(c.clone());
        }
        let (mut scope, _) = types::scope(self.database()?, &edits);
        let id = scope.lookup(key)?;
        scope.definition(id)
    }

    /// The struct or union `key` names as C as it stands, and what an
    /// edit of it edits: a synthesised struct's user's version
    /// ([`Typed::Struct`]; its C the user's, else as the C prints it),
    /// else (`None`) a definition (the user's, else the type library's,
    /// which the user's then replaces).
    pub fn struct_c(&self, key: &str) -> Option<(Option<Typed>, String)> {
        if let Some(listed) = self.synthesised()
            && let Some(found) = listed.iter().find(|s| s.key == key)
        {
            return Some((Some(found.typed()), found.c.clone()));
        }
        // While the table is found again (after a type edit), the user's
        // versions still name theirs.
        let stated = self
            .shared
            .state()
            .edits
            .types()
            .iter()
            .find(|(typed, c)| {
                matches!(typed, Typed::Struct { .. }) && definition_in(c, key).is_some()
            })
            .map(|(typed, c)| (Some(typed.clone()), c.clone()));
        stated.or_else(|| Some((None, self.definition_text(key)?)))
    }

    /// Whether C `c`, the struct or union `key` with its member `member`
    /// edited as `edit` says, still holds the struct's layout: no other
    /// member moves, the size stays, a retype keeps the member's width (a
    /// resize may take the unused bytes up to the next member), a new
    /// name is no other member's. Nothing is changed.
    ///
    /// # Errors
    ///
    /// The C is refused (the bytes at fault), or the layout would not
    /// hold (the member's declaration at fault); no such struct or
    /// member.
    pub fn check_member(
        &self,
        key: &str,
        member: &str,
        edit: &MemberEdit,
        c: &str,
    ) -> Result<(), Error> {
        let refuse = |message: String, span| Error::Type(CError { message, span });
        let (_, now) = self
            .struct_c(key)
            .ok_or_else(|| refuse(format!("no struct or union {key}"), 0..0))?;
        let before = self.struct_layout(&now)?;
        let after = self.struct_layout(c)?;
        let renamed = match edit {
            MemberEdit::Rename(name) => name.as_str(),
            MemberEdit::Retype(_) | MemberEdit::Resize(_) => member,
        };
        let at = member_at(c, renamed).map_or(0..c.len(), |at| at.declaration);
        members::holds(&before, &after, member, edit).map_err(|why| refuse(why, at))
    }

    /// The C of the struct or union `key` with its member `member` edited
    /// as `edit` says, checked ([`Self::check_member`]); nothing is
    /// changed.
    ///
    /// # Errors
    ///
    /// No such struct or member; the name is no C identifier; the C is
    /// refused or the layout would not hold.
    pub fn member_edited(
        &self,
        key: &str,
        member: &str,
        edit: &MemberEdit,
    ) -> Result<String, Error> {
        let refuse = |message: String| {
            Error::Type(CError {
                message,
                span: 0..0,
            })
        };
        if let MemberEdit::Rename(name) = edit
            && !members::is_identifier(name)
        {
            return Err(refuse(format!("{name:?} is not a C identifier")));
        }
        let (_, now) = self
            .struct_c(key)
            .ok_or_else(|| refuse(format!("no struct or union {key}")))?;
        let (c, _) = members::edited(&now, member, edit)
            .ok_or_else(|| refuse(format!("{key} declares no member {member}")))?;
        match self.check_member(key, member, edit, &c) {
            Ok(()) => Ok(c),
            // A resize may take the padding array after the member.
            Err(refused @ Error::Type(_)) if matches!(edit, MemberEdit::Resize(_)) => {
                let before = self.struct_layout(&now)?;
                let size = self
                    .struct_layout(&c)?
                    .members
                    .iter()
                    .find(|m| m.name == member)
                    .map_or(0, |m| m.size);
                let absorbed = members::absorb_padding(&c, &before, member, size).ok_or(refused)?;
                self.check_member(key, member, edit, &absorbed)?;
                Ok(absorbed)
            }
            Err(refused) => Err(refused),
        }
    }

    /// Edits member `member` of the struct or union `key` as `edit` says
    /// ([`Self::member_edited`]): as the struct editor applies a struct,
    /// the user's version of a synthesised struct, else the user's
    /// definition. What changed: every document the struct reaches,
    /// decompiled again.
    ///
    /// # Errors
    ///
    /// As [`Self::member_edited`]; nothing is changed.
    pub fn edit_member(
        &self,
        key: &str,
        member: &str,
        edit: &MemberEdit,
    ) -> Result<Arc<Change>, Error> {
        let c = self.member_edited(key, member, edit)?;
        match self.struct_c(key) {
            Some((Some(typed), _)) => self.set_type(typed, Some(&c)),
            Some((None, _)) | None => self.define(&c).map(|(_, change)| change),
        }
    }

    /// The program's synthesised structs, as the whole-program table
    /// found them last, each with its definition as the C prints it (the
    /// user's version's where there is one): the same list until the
    /// table is found again (after a type edit). `None` while no table is
    /// known: before the callers pass, or while it runs again. Never waits
    /// for the table.
    pub fn synthesised(&self) -> Option<Arc<Vec<Synthesised>>> {
        let database = self.database()?;
        let callers = database.known_callers(&[])?;
        let stated: Vec<(Typed, String)> = self
            .shared
            .state()
            .edits
            .types()
            .iter()
            .filter(|(typed, _)| matches!(typed, Typed::Struct { .. }))
            .map(|(typed, c)| (typed.clone(), c.clone()))
            .collect();
        let mut cache = self
            .synthesised
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((table, then, listed)) = cache.as_ref()
            && table
                .upgrade()
                .is_some_and(|table| Arc::ptr_eq(&table, &callers))
            && *then == stated
        {
            return Some(Arc::clone(listed));
        }
        let edits = self.shared.state().edits.clone();
        let listed = Arc::new(types::synthesised(
            database,
            &callers,
            &edits,
            &self.shared.style(),
        ));
        *cache = Some((Arc::downgrade(&callers), stated, Arc::clone(&listed)));
        Some(listed)
    }

    /// The one type of the global object holding `address` over the
    /// whole program ([`Database::global_type`]: every function's
    /// evidence joined, the user's type above all), with its name (the
    /// user's, else its symbol, else `g_<address>`), its declaration as
    /// the C prints it and its fields with the references into each
    /// ([`Database::global_fields`]: the hex view's overlay and counts),
    /// as the whole-program table found it last.
    /// `None` while no table is known (before the callers pass, or while
    /// it runs again after a type edit), or where no function reaches the
    /// global. Never waits for the table. A user's type for it is set
    /// with [`Self::set_type`] on [`Typed::Global`].
    pub fn global_type(&self, address: u64) -> Option<GlobalTyped> {
        let database = self.database()?;
        let callers = database.known_callers(&[])?;
        let start = database.global_start(address);
        let ty = callers.schemes.globals().get(start)?.clone();
        let name = self.global_name(start);
        let c = database.global_declaration(&callers, &ty, &name, &self.shared.style());
        let fields = database.global_fields(&callers, &ty);
        Some(GlobalTyped {
            ty,
            name,
            c,
            fields,
        })
    }

    /// The name of the global starting at `start` as the C names it: the
    /// user's, else its symbol, else `g_<address>`.
    pub fn global_name(&self, start: u64) -> String {
        self.name(start).unwrap_or_else(|| format!("g_{start:x}"))
    }

    /// The type of the global starting at `start` (as
    /// [`Self::global_type`] has it) in a table of its own
    /// ([`Database::global_table`]) with each of the table's types named
    /// as the C names it: what the hex view lays over the global's bytes.
    /// `None` while no table is known (as for [`Self::global_type`]), where
    /// the table types no global there, or where the image's code is not
    /// lifted. Never waits for the table.
    pub fn global_table(&self, start: u64) -> Option<GlobalTable> {
        let database = self.database()?;
        let callers = database.known_callers(&[])?;
        let ty = callers.schemes.globals().get(start)?;
        let (types, id) = database.global_table(&callers, ty)?;
        let style = &self.shared.style();
        let long = database.data().long_width();
        let names = c::type_names(&types, database.declarations()?, style, long)
            .ok()?
            .iter()
            .map(|name| {
                name.as_ref()
                    .map(|document| render(document, style).trim().to_owned())
            })
            .collect();
        Some(GlobalTable {
            types,
            ty: id,
            names,
        })
    }

    /// Drops the user's definition of `key` (the type library's, if it
    /// defines the key, is the type again); what changed, as for
    /// [`Self::define`].
    ///
    /// # Errors
    ///
    /// The change cannot be made, or the share does not take it
    /// ([`Error::Refused`]).
    pub fn undefine(&self, key: &str) -> Result<Arc<Change>, Error> {
        let change = self.redefined();
        self.write(
            "Undefine type",
            vec![(JournalKey::Definition(key.to_owned()), Value::Text(None))],
            change,
            true,
        )
    }

    /// The documents the user's types of `typed` reach: a variable's
    /// function; a prototype's or a global's function and the functions
    /// referring to it.
    fn reached(&self, typed: &[Typed]) -> Change {
        let mut documents = Vec::new();
        for typed in typed {
            match typed {
                &Typed::Prototype(address) | &Typed::Global(address) => {
                    documents.extend(self.printing(address).documents);
                }
                Typed::Variable(variable) => documents.extend(
                    self.database()
                        .and_then(|database| database.function_at(variable.function)),
                ),
                // A struct is the whole program's: every function
                // decompiled may print it.
                Typed::Struct { .. } => documents.extend(
                    self.shared
                        .state()
                        .decompiled
                        .keys()
                        .map(|&(function, _)| function),
                ),
            }
        }
        documents.sort_unstable();
        documents.dedup();
        Change {
            documents,
            listing: Vec::new(),
        }
    }

    /// The documents a definition (or its removal) reaches: every
    /// function decompiled, as a type of the whole program any of them
    /// may print or use, and those the user's types reach (a type may
    /// name the definition).
    fn redefined(&self) -> Change {
        let typed: Vec<Typed> = self.shared.state().edits.types().keys().cloned().collect();
        let mut change = self.reached(&typed);
        change.documents.extend(
            self.shared
                .state()
                .decompiled
                .keys()
                .map(|&(function, _)| function),
        );
        change.documents.sort_unstable();
        change.documents.dedup();
        change
    }

    /// Saves the changes made and not saved yet, and the edits to the
    /// project file, crash-safely ([`Edits::save`]).
    ///
    /// # Errors
    ///
    /// It cannot be written.
    pub fn save(&self) -> Result<(), Error> {
        let project = self.project().ok_or_else(|| {
            Error::Project(if self.options.ephemeral {
                "the session has no project".to_owned()
            } else {
                "the project is not known yet".to_owned()
            })
        })?;
        let mut state = self.shared.state();
        state.saves += 1;
        let worker::State { journal, edits, .. } = &mut *state;
        journal.save(edits, project).map_err(Error::Project)
    }

    /// Stops the worker at its next step; requests not answered yet are
    /// answered with an error.
    pub fn cancel(&self) {
        self.canceller().cancel();
        self.answers.cancel_running();
    }

    /// What cancels the worker from elsewhere.
    pub fn canceller(&self) -> Canceller {
        Canceller(Arc::clone(&self.shared.cancelled))
    }

    /// Marks the session as closing: its project is let go of soon, so a
    /// session of this process opening it meanwhile waits for it rather
    /// than being refused ([`project::Project::hold`]). What a front end
    /// does as it drops a session other threads may hold a moment longer;
    /// [`Self::close`] does it first. Not if a session that follows this
    /// one ([`Self::reanalysed`]) holds the project too: that one is open.
    pub fn closing(&self) {
        self.shared.closing();
    }

    /// Cancels, waits for the worker to stop, and lets the project go
    /// ([`project::Project::hold`]).
    pub fn close(mut self) {
        self.closing();
        self.cancel();
        self.requests = None;
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        for lane in &mut self.lanes {
            if let Some((jobs, thread)) = lane.take() {
                drop(jobs);
                let _ = thread.join();
            }
        }
        self.shared.release();
    }

    /// Sends `request` to the worker; whether it is running.
    fn send(&self, request: Request) -> bool {
        self.requests
            .as_ref()
            .is_some_and(|requests| requests.send(request).is_ok())
    }

    /// What naming `address` changes: the documents of the functions
    /// referring to it (to any byte of the object holding it) and of the
    /// function starting there, and the listing lines of the references and
    /// of the address itself. Before the cross-references are built, no
    /// document is printed yet, and every listing line may name it.
    fn printing(&self, address: u64) -> Change {
        let Some(database) = self
            .database()
            .filter(|_| self.stage() >= Stage::Referenced)
        else {
            return Change {
                documents: Vec::new(),
                listing: self.database().map(worker::whole).unwrap_or_default(),
            };
        };
        let object = database
            .object(address)
            .unwrap_or(address..address.saturating_add(1));
        let references = database.references().within(object);
        let mut documents: Vec<FunctionId> = references
            .iter()
            .filter_map(|reference| reference.function)
            .chain(database.function_at(address))
            .collect();
        documents.sort_unstable();
        documents.dedup();
        let own = address..address.saturating_add(1);
        let listing = references
            .iter()
            .map(|reference| reference.from..reference.from.saturating_add(1))
            .chain([own])
            .collect();
        Change {
            documents,
            listing: worker::merge(listing),
        }
    }
}

impl Drop for Session {
    /// Cancels; the worker stops at its next step, without waiting for it.
    fn drop(&mut self) {
        if !self.handle {
            self.cancel();
            self.shared.release();
        }
    }
}

/// What a request's answer says once the worker stopped.
const STOPPED: &str = "the session's worker stopped";

/// `name`, but `None` if empty.
fn given(name: Option<&str>) -> Option<String> {
    name.filter(|name| !name.is_empty()).map(str::to_owned)
}

/// The one variable of `l2` among `printed` made from the frame slot at
/// `offset` and from no other slot (or, made from none, living there), if
/// exactly one is.
fn slot_variable(l2: &Ast, printed: &BTreeSet<VarId>, offset: i64) -> Option<VarId> {
    let mut holding = printed.iter().copied().filter(|&var| {
        let Some(variable) = l2.var(var) else {
            return false;
        };
        let mut slots = variable.origins.iter().filter_map(|origin| match *origin {
            Origin::Slot(at) => Some(at),
            Origin::Value(_)
            | Origin::Instruction(_)
            | Origin::Register(_)
            | Origin::Held(_)
            | Origin::Block(_)
            | Origin::Absorbed(_)
            | Origin::Proved => None,
        });
        match (slots.next(), slots.next()) {
            (Some(at), None) => at == offset,
            (Some(_), Some(_)) => false,
            (None, _) => matches!(variable.kind, VarKind::Frame(at) if at == offset),
        }
    });
    match (holding.next(), holding.next()) {
        (Some(var), None) => Some(var),
        (Some(_), Some(_)) | (None, _) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use binbun_ast::ir::{Function as Ast, Origin, VarId, VarKind, Variable};
    use binbun_ast::types::{Evidence, TypeId, Types};

    use super::slot_variable;

    /// A variable of `kind` made from `origins`.
    fn variable(kind: VarKind, origins: &[Origin]) -> Variable {
        Variable {
            kind,
            name: None,
            ty: TypeId(0),
            evidence: Evidence::Default,
            origins: origins.to_vec(),
        }
    }

    #[test]
    fn a_slot_is_the_one_printed_variable_made_from_it_alone() {
        let mut l2 = Ast::new(0, Types::new(64));
        let slot = |at| Origin::Slot(at);
        // -92: printed, and a copy the C does not print (as bash's main
        // has): the printed one is the slot.
        let argc = l2.add_var(variable(VarKind::Local, &[slot(-92)]));
        let copy = l2.add_var(variable(VarKind::Local, &[slot(-92)]));
        // -80: two printed variables, neither is it.
        let a = l2.add_var(variable(VarKind::Local, &[slot(-80)]));
        let b = l2.add_var(variable(VarKind::Local, &[slot(-80)]));
        // -128: printed only as part of two slots; the one made from it
        // alone is not printed.
        let pair = l2.add_var(variable(VarKind::Local, &[slot(-144), slot(-128)]));
        let hidden = l2.add_var(variable(VarKind::Local, &[slot(-128)]));
        // -24: made from nothing, living there.
        let frame = l2.add_var(variable(VarKind::Frame(-24), &[]));
        let printed: BTreeSet<VarId> = [argc, a, b, pair, frame].into();
        assert_eq!(slot_variable(&l2, &printed, -92), Some(argc));
        assert_eq!(slot_variable(&l2, &printed, -80), None);
        assert_eq!(slot_variable(&l2, &printed, -128), None);
        assert_eq!(slot_variable(&l2, &printed, -144), None);
        assert_eq!(slot_variable(&l2, &printed, -24), Some(frame));
        // Everything printed: -92 is two variables, -128 the hidden one.
        let all: BTreeSet<VarId> = [argc, copy, a, b, pair, hidden, frame].into();
        assert_eq!(slot_variable(&l2, &all, -92), None);
        assert_eq!(slot_variable(&l2, &all, -128), Some(hidden));
    }
}
