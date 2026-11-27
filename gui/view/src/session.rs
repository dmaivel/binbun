//! One binary opened for the GUI: a `binbun-session` lineage (the session
//! in use and one analysing anew), and around it what the views need,
//! without blocking the UI thread.
//!
//! - A **pump** thread turns the lineage's events into [`Event`]s: a C
//!   document becomes a [`CDocument`] (provenance and tints computed
//!   there, not on the UI thread); the functions recovered start the
//!   listing's build, the cross-references the strings', each on a thread
//!   of its own. `wake` is called after each event; [`Session::poll`]
//!   takes them on the UI thread.
//! - The **documents** of each function in each view are kept (the
//!   latest, even when an edit made it stale, until the new one comes).
//!   One that cannot be printed is kept as why ([`Session::failure`]) and
//!   not asked for again until an edit or a new analysis could change it.
//! - **Edits** (renames, comments, numbers' forms, types) go through the
//!   session's journal (saved to the project) and are undone and made
//!   again there ([`binbun_session::Session::undo`]); the user's names,
//!   comments, bookmarks and numbers' forms are the session's
//!   [`Overlay`], kept here as of the last edit or event.
//! - **Searches** ([`Session::find_in_listing`], [`Session::search_text`],
//!   [`Session::search_immediate`], [`Session::search_bytes`]) are the
//!   session's, on threads of their own, their results streamed
//!   ([`Search`]), `wake` called as they come.
//! - **Debug information from a symbol server** (`symbols.download`):
//!   the bar's state ([`SymbolsBar`]) follows the session's; once fetched,
//!   the binary is opened again with it ([`Lineage::with_debug`]) beside
//!   the one shown, which is replaced once its functions are recovered
//!   ([`Lineage::swap`], [`Event::Reopened`]), taking the edits made
//!   meanwhile: every document kept is then stale and shown until its new
//!   one comes.
//! - **Corrections** of recovery (`C`, `U`, `D`, `A`, `*`, `P`, Edit
//!   and Delete Function: [`crate::corrections`]) are undoable edits that
//!   recover anew: the binary is analysed again with them
//!   ([`Lineage::reanalyse`]: its bytes and image kept)
//!   beside the one shown and replaces it as a download does, once its
//!   functions are recovered; functions keep their documents by entry
//!   ([`Event::Reopened`] says which function is which now), and one
//!   made meanwhile is analysed again.
//! - **Scripts** connected over the socket write through the session's
//!   [`Host`] ([`Session::host`]), the one the GUI's edits go through
//!   too: while a script's transaction is open the GUI's edits are
//!   refused (said as [`Event::Failed`]), and a new analysis is swapped
//!   in only between writes ([`Host::swap`]).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

use binbun::Database;
use binbun::cfg::FunctionId;
use binbun::corrections::Corrections;
use binbun::strings::Encoding;
use binbun_ast::ir::VarId;
use binbun_print::style::Style;
use binbun_protocol::Host;
use binbun_session::journal::Origin;
use binbun_session::journal::{Key as JournalKey, OpId, PublicKey, Value};
use binbun_session::number::{Radix, Written, by_name};
use binbun_session::signatures::NameSource;
use binbun_session::signatures::Options as SignatureOptions;
use binbun_session::talk::{Anchor, Mentioned, Say, Suggestion, Talked, Thread};
use binbun_session::{
    Answer, Asked, CError, Change, Conflict, Download, Event as SessionEvent, GlobalTable,
    GlobalTyped, HistoryEntry, Lineage, Located, MemberEdit, NumberForm, Options, Question,
    Rechecked, Refused, Stage, StructLayout, SymbolState, Symbols, Synthesised, TypeLayout, Typed,
    View,
};
pub use binbun_session::{Project, project};

use crate::cdoc::CDocument;
use crate::listing::{Listing, Options as ListingOptions, Overlay};
use crate::search::{ByteHit, BytePattern, Hit, Matcher, Plan, Search, TextHit};
use crate::settings::SymbolDownload;
use crate::structedit::StructTarget;
use crate::symbols::{Bar, SymbolsBar};

/// Wakes the UI's event loop.
pub type Wake = Arc<dyn Fn() + Send + Sync>;

/// No library function named, no pack read: the tests' sessions.
#[cfg(test)]
pub(crate) fn without_signatures() -> SignatureOptions {
    SignatureOptions {
        enabled: false,
        ..SignatureOptions::default()
    }
}

/// How long a poll waits, after a swap, for the pump to pass what the
/// session replaced told (it is dropped).
const SWAPPED: Duration = Duration::from_secs(2);

/// How long a suggestion's evidence is asked again, at most per item (a
/// verification can take a while).
const RECHECK: Duration = Duration::from_secs(120);

/// Others' bookmarks, by author, then address.
pub type Shelves = BTreeMap<PublicKey, BTreeMap<u64, String>>;

/// A string literal of the image, for the strings list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringItem {
    /// Its address.
    pub address: u64,
    /// Its text.
    pub text: String,
    /// Its size in the image, in bytes (its terminator aside).
    pub size: u64,
    /// Whether it is UTF-16 (else UTF-8).
    pub wide: bool,
}

/// Something that happened, for the UI.
#[derive(Clone, Debug)]
pub enum Event {
    /// A stage of the analysis is reached.
    Stage(Stage),
    /// The listing is built (under the options it carries).
    Listing(Arc<Listing>),
    /// The strings are found.
    Strings(Arc<Vec<StringItem>>),
    /// A function's C in a view arrived (kept: [`Session::document`]).
    Document {
        /// The function.
        function: FunctionId,
        /// The view.
        view: View,
        /// Its document, or why there is none.
        result: Result<Arc<CDocument>, String>,
    },
    /// An edit or a stage changed documents or listing lines.
    Changed(Arc<Change>),
    /// The answer to a question ([`Session::ask`]).
    Answer {
        /// The question's number.
        request: u64,
        /// The function asked about.
        function: FunctionId,
        /// The view.
        view: View,
        /// The answer.
        answer: Answer,
    },
    /// Opening failed, an edit could not be saved, or edits do not
    /// resolve.
    Failed(String),
    /// What became of the binary's debug information on a symbol server
    /// changed ([`Session::symbols_bar`]).
    Symbols(SymbolState),
    /// The binary was opened again with the debug information fetched:
    /// questions asked before are not answered; documents come again.
    /// Or analysed again with the corrections: the functions there are
    /// now by their old ids (a function gone has none).
    Reopened(Arc<HashMap<FunctionId, FunctionId>>),
    /// Changes entered the history (made here or by a peer), newest
    /// first, each with its author.
    History(Arc<[HistoryEntry]>),
    /// The keys whose concurrent edits left more than one value: every
    /// conflict now.
    Conflicts(Arc<[Conflict]>),
    /// Conversation came, made here or by a peer: threads and suggestions
    /// with something new.
    Talked(Arc<Talked>),
    /// A new post mentions this identity (or one of its scripts or
    /// agents).
    Mentioned(Arc<Mentioned>),
    /// Others' bookmarks or this person's private ones changed
    /// ([`Session::others_bookmarks`], [`Session::private_bookmarks`]).
    Bookmarks,
    /// A suggestion's evidence asked again ([`Session::recheck`]), item by
    /// item.
    Rechecked {
        /// The suggestion.
        suggestion: OpId,
        /// Its items now.
        items: Arc<[Rechecked]>,
    },
}

/// A function in a view, as a key.
type Key = (FunctionId, bool);

fn key(function: FunctionId, view: View) -> Key {
    (function, view == View::Reading)
}

/// The symbol servers and stores, debug information fetched as
/// `download` says.
fn symbols(download: SymbolDownload) -> Symbols {
    let download = match download {
        SymbolDownload::Ask => Download::Ask,
        SymbolDownload::Always => Download::Always,
        SymbolDownload::Never => Download::Never,
    };
    Symbols {
        download,
        ..Symbols::default()
    }
}

/// What the pump and the listing builds share with the session.
#[derive(Debug, Default)]
struct Wanted {
    /// The listing's options last asked for.
    listing: ListingOptions,
    /// Whether the functions are recovered (a listing can be built).
    analysed: bool,
    /// Whether the strings are looked for (the references are built).
    referenced: bool,
    /// The view each request without an answer yet asked for.
    views: HashMap<u64, View>,
}

/// One opened binary.
pub struct Session {
    /// The binary's sessions: the one in use and one analysing anew.
    lineage: Arc<Lineage>,
    /// Who writes to them: the user here, scripts over the socket.
    host: Arc<Host>,
    /// The session in use.
    inner: Arc<binbun_session::Session>,
    events: Receiver<Event>,
    sender: Sender<Event>,
    wake: Wake,
    wanted: Arc<Mutex<Wanted>>,
    documents: HashMap<Key, Arc<CDocument>>,
    stale: HashSet<Key>,
    /// The documents that could not be printed, and why: not asked for
    /// again until a change could make them print (cleared as the
    /// documents kept go stale).
    failed: HashMap<Key, String>,
    pending: HashSet<Key>,
    overlay: Arc<Overlay>,
    /// The others' bookmarks, by author, as of the last event.
    others: Shelves,
    /// This person's private bookmarks, as of the last event.
    private: BTreeMap<u64, String>,
    /// The symbol server bar.
    bar: SymbolsBar,
    /// The slice of a universal Mach-O file asked for, if one was.
    arch: Option<String>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("path", &self.inner.path())
            .field("stage", &self.inner.stage())
            .finish_non_exhaustive()
    }
}

impl Drop for Session {
    /// The window lets go of the session: its project is let go of as soon
    /// as the threads still holding it a moment do, and opening it again
    /// meanwhile waits for that ([`binbun_session::Session::closing`]).
    fn drop(&mut self) {
        self.inner.closing();
    }
}

impl Session {
    /// Opens the binary at `path`: returns at once, the analysis running;
    /// `wake` is called after each event (on another thread). Its debug
    /// information is fetched from a symbol server as `download` says. Its
    /// project is the directory `project` (`None`: its own in binbun's
    /// data directory, found by its bytes). Its library functions are
    /// named as `signatures` says. Of a universal Mach-O file, the slice
    /// of architecture `arch` is opened (`None`: this machine's
    /// instruction set's, else the first).
    ///
    /// # Errors
    ///
    /// The session cannot start.
    pub fn open(
        path: PathBuf,
        arch: Option<String>,
        project: Option<PathBuf>,
        listing: ListingOptions,
        download: SymbolDownload,
        signatures: SignatureOptions,
        wake: Wake,
    ) -> Result<Self, String> {
        Self::open_with(
            path,
            arch,
            project,
            None,
            listing,
            symbols(download),
            signatures,
            wake,
        )
    }

    /// [`Self::open`] with the projects and the identity kept in `home`'s
    /// `projects` and `identity` (`None`: binbun's data and configuration
    /// directories), naming no library functions (no pack is read).
    #[cfg(test)]
    pub(crate) fn open_in(
        path: PathBuf,
        home: Option<&Path>,
        listing: ListingOptions,
        download: SymbolDownload,
        wake: Wake,
    ) -> Result<Self, String> {
        Self::open_with(
            path,
            None,
            None,
            home,
            listing,
            symbols(download),
            without_signatures(),
            wake,
        )
    }

    /// [`Self::open_in`] of the slice `arch` in the project directory
    /// `project` (`None`: its own in `home`'s or binbun's projects) with
    /// the symbol servers and stores of `symbols` (tests: a local server),
    /// naming library functions as `signatures` says.
    #[expect(clippy::too_many_arguments, reason = "what a session opens with")]
    pub(crate) fn open_with(
        path: PathBuf,
        arch: Option<String>,
        project: Option<PathBuf>,
        home: Option<&Path>,
        listing: ListingOptions,
        symbols: Symbols,
        signatures: SignatureOptions,
        wake: Wake,
    ) -> Result<Self, String> {
        let lineage = Arc::new(
            Lineage::open(
                path,
                Options {
                    project,
                    projects: home.map(|home| home.join("projects")),
                    identity: home.map(|home| home.join("identity")),
                    symbols,
                    arch: arch.clone(),
                    signatures,
                    ..Options::default()
                },
            )
            .map_err(|error| error.to_string())?,
        );
        Self::of_lineage(lineage, arch, listing, wake)
    }

    /// The session of `lineage`, opened (it may be analysed already: what
    /// it reached is told first), the listing built under `listing` once
    /// its functions are recovered; `arch`: the slice asked for.
    fn of_lineage(
        lineage: Arc<Lineage>,
        arch: Option<String>,
        listing: ListingOptions,
        wake: Wake,
    ) -> Result<Self, String> {
        let inner = lineage.session();
        // The lineage's events pumped (each followed by `wake`), the
        // listing built under `listing` once the functions are recovered.
        let (sender, events) = mpsc::channel();
        let wanted = Arc::new(Mutex::new(Wanted {
            listing,
            ..Wanted::default()
        }));
        let received = lineage.subscribe(None);
        {
            let lineage = Arc::downgrade(&lineage);
            let sender = sender.clone();
            let wake = Arc::clone(&wake);
            let wanted = Arc::clone(&wanted);
            thread::Builder::new()
                .name("binbun-gui-pump".to_owned())
                .spawn(move || pump(&lineage, &received, &sender, &wake, &wanted))
                .map_err(|error| format!("cannot start a thread: {error}"))?;
        }
        let overlay = inner.overlay();
        let others = inner.others_bookmarks();
        let private = inner.private_bookmarks();
        Ok(Self {
            host: Arc::new(Host::new(Arc::clone(&lineage), false)),
            lineage,
            inner,
            events,
            sender,
            wake,
            wanted,
            documents: HashMap::new(),
            stale: HashSet::new(),
            failed: HashMap::new(),
            pending: HashSet::new(),
            overlay,
            others,
            private,
            bar: SymbolsBar::default(),
            arch,
        })
    }

    /// The binary's path.
    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    /// Who writes to the binary's sessions: the user's edits here and
    /// scripts' over the socket (the server serves this host).
    pub fn host(&self) -> &Arc<Host> {
        &self.host
    }

    /// Makes the user's edit `edit` on the session in use, unless a
    /// script's transaction is open (then why not).
    fn as_user<R>(&self, edit: impl FnOnce(&binbun_session::Session) -> R) -> Result<R, String> {
        let inner = &self.inner;
        self.host
            .exclusive(|| edit(inner))
            .map_err(|fault| fault.message)
    }

    /// Says why an edit that returns nothing was refused.
    fn refuse(&self, why: String) {
        let _ = self.sender.send(Event::Failed(why));
        (self.wake)();
    }

    /// The binary's file name.
    pub fn file_name(&self) -> String {
        let path = self.inner.path();
        path.file_name().map_or_else(
            || path.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        )
    }

    /// The architecture of the slice of a universal Mach-O file open: the
    /// one parsed, else (before) the one asked for; `None` for any other
    /// file.
    pub fn slice(&self) -> Option<&str> {
        match self.inner.image() {
            Some(_) => self.inner.slice(),
            None => self.arch.as_deref(),
        }
    }

    /// The stage reached.
    pub fn stage(&self) -> Stage {
        self.inner.stage()
    }

    /// The functions done and the total of the whole-program pass
    /// running ([`binbun_session::Session::progress`]).
    pub fn progress(&self) -> Option<(usize, usize)> {
        self.inner.progress()
    }

    /// The database, once the functions are recovered.
    pub fn database(&self) -> Option<&Database<'_>> {
        self.inner.database()
    }

    /// How far the session's state has come
    /// ([`binbun_session::Session::revision`]): what was read from it is
    /// current while it is the same.
    pub fn revision(&self) -> binbun_session::Revision {
        self.inner.revision()
    }

    /// The source file (its path) the debug information states the
    /// function at `entry` is defined in, if a debug file was found.
    pub fn source_file(&self, entry: u64) -> Option<String> {
        self.inner
            .source_unit(entry)
            .map(binbun_session::Unit::path)
    }

    /// What a library signature says of the function at `entry`, if a
    /// match is applied there (not one the user rejected).
    pub fn signature(&self, entry: u64) -> Option<binbun_session::Identified> {
        self.inner.signature(entry).filter(|i| !i.rejected)
    }

    /// What a library signature says of the function at `entry`, a match
    /// the user rejected too.
    pub fn signature_record(&self, entry: u64) -> Option<binbun_session::Identified> {
        self.inner.signature(entry)
    }

    /// Where the name of the function at `entry` comes from
    /// ([`binbun_session::Session::name_source`]); `None` for a name
    /// binbun made.
    pub fn name_source(&self, entry: u64) -> Option<NameSource> {
        self.inner.name_source(entry)
    }

    /// Rejects the signature match of the function at `entry`
    /// ([`binbun_session::Session::reject_signature`]).
    ///
    /// # Errors
    ///
    /// No match is applied there, or a group of edits is open.
    pub fn reject_signature(&mut self, entry: u64) -> Result<(), String> {
        self.inner
            .reject_signature(entry)
            .map_err(|error| error.to_string())?;
        self.edited();
        Ok(())
    }

    /// The file's bytes and the image parsed from them, once parsed.
    pub fn loaded(&self) -> Option<(&[u8], &binbun_loader::Image<'_>)> {
        Some((self.inner.bytes()?, self.inner.image()?))
    }

    /// The session in use (a newer analysis takes its place at a swap:
    /// [`Event::Reopened`]): what a shared session's peer drives.
    pub fn core(&self) -> Arc<binbun_session::Session> {
        Arc::clone(&self.inner)
    }

    /// The keys in conflict now.
    pub fn conflicts(&self) -> Vec<Conflict> {
        self.inner.conflicts()
    }

    /// Resolves the conflict on `key` with `value` (one of its values):
    /// one value again for everyone.
    ///
    /// # Errors
    ///
    /// The value is not one of the key's.
    pub fn resolve(&mut self, key: JournalKey, value: Value) -> Result<(), String> {
        self.inner
            .resolve(key, value)
            .map_err(|error| error.to_string())?;
        self.edited();
        Ok(())
    }

    /// The changes this session refused (signatures, chains, projects).
    pub fn refused(&self) -> Vec<Refused> {
        self.inner.refused()
    }

    /// After changes taken from a peer: the binary analysed again if
    /// their corrections need it.
    pub fn took_remote(&mut self) {
        self.edited();
    }

    /// The user's names and comments.
    pub fn overlay(&self) -> &Overlay {
        &self.overlay
    }

    /// The events since the last poll, the documents kept and the edits'
    /// overlay brought up to date first. The binary opened again with
    /// fetched debug information replaces the one shown here once its
    /// functions are recovered ([`Lineage::swap`]; [`Event::Reopened`]
    /// first, what the one replaced told before it dropped).
    pub fn poll(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        if self.host.swap().is_some() {
            // The edits made while it was being analysed came along.
            self.inner = self.lineage.session();
            // Corrections made meanwhile are analysed anew again.
            if self.lineage.reanalysing() {
                self.wake_when_ready();
            }
            // What the one replaced told before the swap is dropped: the
            // pump tells the swap (`Reopened`) after it.
            let deadline = Instant::now() + SWAPPED;
            while let Some(left) = deadline.checked_duration_since(Instant::now()) {
                match self.events.recv_timeout(left) {
                    Ok(Event::Reopened(functions)) => {
                        self.renumber(&functions);
                        events.push(Event::Reopened(functions));
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
        events.extend(self.events.try_iter());
        // The session in use has debug information (swapped in after a
        // download, a peer's file, or given): the bar has nothing to offer
        // for this binary any more, whatever was told for the one before.
        if self.inner.debug_file().is_some() {
            self.bar.debugged();
        }
        let mut fetched = None;
        for event in &events {
            match event {
                Event::Document {
                    function,
                    view,
                    result,
                } => {
                    let k = key(*function, *view);
                    self.pending.remove(&k);
                    match result {
                        Ok(document) => {
                            self.documents.insert(k, Arc::clone(document));
                            self.stale.remove(&k);
                            self.failed.remove(&k);
                        }
                        Err(why) => {
                            // What it printed before reads otherwise now.
                            self.documents.remove(&k);
                            self.stale.remove(&k);
                            self.failed.insert(k, why.clone());
                        }
                    }
                }
                Event::Changed(change) => {
                    for &function in &change.documents {
                        for view in [View::Exact, View::Reading] {
                            let k = key(function, view);
                            if self.documents.contains_key(&k) {
                                self.stale.insert(k);
                            }
                            self.failed.remove(&k);
                        }
                    }
                    self.overlay = self.inner.overlay();
                }
                // The project's edits are loaded once the image is parsed
                // (a stage told late may be a later one).
                Event::Stage(_) => {
                    self.overlay = self.inner.overlay();
                    self.shelve();
                }
                Event::Bookmarks => self.shelve(),
                Event::Symbols(state) => fetched = self.bar.update(state.clone()),
                // A change made elsewhere (a signatures' run, a peer's)
                // may correct recovery: analysed anew if it did.
                Event::History(_) => self.reanalyse(),
                Event::Listing(_)
                | Event::Strings(_)
                | Event::Failed(_)
                | Event::Answer { .. }
                | Event::Reopened(_)
                | Event::Conflicts(_)
                | Event::Talked(_)
                | Event::Mentioned(_)
                | Event::Rechecked { .. } => {}
            }
        }
        if let Some(path) = fetched {
            self.reopen(path);
        }
        events
    }

    /// Keeps each function's documents by its id now (`functions`: by
    /// its id before), stale until its new one comes.
    fn renumber(&mut self, functions: &HashMap<FunctionId, FunctionId>) {
        self.documents = std::mem::take(&mut self.documents)
            .into_iter()
            .filter_map(|((function, reading), document)| {
                let now = *functions.get(&function)?;
                let document = if now == function {
                    document
                } else {
                    let mut renumbered = (*document).clone();
                    renumbered.function = now;
                    Arc::new(renumbered)
                };
                Some(((now, reading), document))
            })
            .collect();
        self.stale.extend(self.documents.keys().copied());
        self.failed.clear();
        self.pending.clear();
        self.overlay = self.inner.overlay();
        self.shelve();
    }

    /// Opens the binary again with the debug information at `path`, beside
    /// the one shown (which [`Self::poll`] replaces once its functions are
    /// recovered).
    fn reopen(&mut self, path: PathBuf) {
        match self.lineage.with_debug(path) {
            Ok(()) => self.wake_when_ready(),
            Err(error) => {
                let _ = self.sender.send(Event::Failed(error.to_string()));
                (self.wake)();
            }
        }
    }

    /// Analyses the binary again with the debug file at `path` (one a
    /// peer sent), beside the one shown, which [`Self::poll`] replaces
    /// once its functions are recovered ([`Event::Reopened`]).
    pub fn analyse_with_debug(&mut self, path: PathBuf) {
        self.reopen(path);
    }

    /// What the symbol server bar shows, if anything.
    pub fn symbols_bar(&self) -> Option<Bar> {
        self.bar.bar()
    }

    /// Analyses the binary again with the corrections the edits hold now,
    /// beside the one shown (which [`Self::poll`] replaces once its
    /// functions are recovered), if they changed; after the one under way,
    /// if one is ([`Lineage::reanalyse`]).
    fn reanalyse(&self) {
        match self.lineage.reanalyse() {
            Ok(true) => self.wake_when_ready(),
            Ok(false) => {}
            Err(error) => {
                let _ = self.sender.send(Event::Failed(error.to_string()));
                (self.wake)();
            }
        }
    }

    /// Wakes the front end once the new analysis under way can take the
    /// one shown's place: its events are held until then, so nothing else
    /// would ([`Self::poll`] swaps it in). Without it an idle window never
    /// showed a correction (Delete Function did nothing).
    fn wake_when_ready(&self) {
        let lineage = Arc::downgrade(&self.lineage);
        let wake = Arc::clone(&self.wake);
        // Asked again now and then, so a session closed meanwhile goes.
        let spawned = thread::Builder::new()
            .name("binbun-gui-reanalysis".to_owned())
            .spawn(move || {
                while let Some(lineage) = lineage.upgrade() {
                    match lineage.ready(Some(Duration::from_millis(250))) {
                        Some(true) => {
                            wake();
                            return;
                        }
                        Some(false) => {}
                        None => return,
                    }
                }
            });
        if let Err(error) = spawned {
            let _ = self
                .sender
                .send(Event::Failed(format!("cannot start a thread: {error}")));
            (self.wake)();
        }
    }

    /// The user's corrections of recovery.
    pub fn corrections(&self) -> Corrections {
        self.inner.corrections()
    }

    /// Whether the binary is being analysed again (with corrections, or
    /// debug information fetched).
    pub fn reanalysing(&self) -> bool {
        self.lineage.reanalysing()
    }

    /// Takes `after` as the user's corrections of recovery (an undoable
    /// edit) and analyses the binary again with them.
    ///
    /// # Errors
    ///
    /// The session refuses one (why).
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the views hand over the corrections they made"
    )]
    pub fn correct(&mut self, after: Corrections) -> Result<(), String> {
        if self.inner.corrections() == after {
            return Ok(());
        }
        self.as_user(|inner| {
            inner
                .set_corrections(&after)
                .map_err(|error| error.to_string())
        })??;
        self.edited();
        Ok(())
    }

    /// Download: fetches the binary's debug information offered (the bar
    /// shows the download); whether it started.
    pub fn fetch_symbols(&self) -> bool {
        self.inner.fetch_symbols()
    }

    /// Not now, or a failure dismissed: puts the bar away until something
    /// new happens (Not now: until the binary is opened again).
    pub fn dismiss_symbols(&mut self) {
        self.bar.dismiss();
    }

    /// Asks `question` of `function` in `view` (on the session's lanes):
    /// what cancels it; the [`Event::Answer`] with its number answers it.
    pub fn ask(&self, function: FunctionId, view: View, question: Question) -> Asked {
        self.inner.ask(function, view, question)
    }

    /// The answer kept to `question` of `function` in `view`.
    pub fn answer(&self, function: FunctionId, view: View, question: &Question) -> Option<Answer> {
        self.inner.answer(function, view, question)
    }

    /// The binary's project (its edits, layout, overlays, Pathfinder
    /// question and example states), once the image is parsed.
    pub fn project(&self) -> Option<&Project> {
        self.inner.project()
    }

    /// The binary's key (SHA-256 and file name), once the image is parsed.
    pub fn key(&self) -> Option<&project::Key> {
        self.inner.key()
    }

    /// Function `function`'s document in `view` as last printed (stale if
    /// an edit changed it and the new one has not come yet).
    pub fn document(&self, function: FunctionId, view: View) -> Option<&Arc<CDocument>> {
        self.documents.get(&key(function, view))
    }

    /// Whether a document of `function` in `view` is on its way.
    pub fn is_pending(&self, function: FunctionId, view: View) -> bool {
        self.pending.contains(&key(function, view))
    }

    /// Why `function`'s document in `view` could not be printed, if it
    /// could not (and nothing changed it since).
    pub fn failure(&self, function: FunctionId, view: View) -> Option<&str> {
        self.failed.get(&key(function, view)).map(String::as_str)
    }

    /// Asks for `function`'s document in `view` unless it is kept and up to
    /// date, already asked for, or could not be printed and nothing
    /// changed it since; whether it asked.
    pub fn ensure(&mut self, function: FunctionId, view: View) -> bool {
        let k = key(function, view);
        if self.pending.contains(&k)
            || self.failed.contains_key(&k)
            || (self.documents.contains_key(&k) && !self.stale.contains(&k))
        {
            return false;
        }
        self.pending.insert(k);
        let mut wanted = self.wanted.lock().unwrap_or_else(PoisonError::into_inner);
        let request = self.inner.request_view(function, view);
        wanted.views.insert(request, view);
        true
    }

    /// Builds the listing again under `options` (on a thread); the
    /// [`Event::Listing`] carries them.
    pub fn relist(&self, options: ListingOptions) {
        let mut wanted = self.wanted.lock().unwrap_or_else(PoisonError::into_inner);
        wanted.listing = options.clone();
        if wanted.analysed {
            build_listing(
                Arc::downgrade(&self.lineage),
                options,
                self.sender.clone(),
                Arc::clone(&self.wake),
            );
        }
    }

    /// The style the C is laid out in now.
    pub fn style(&self) -> Style {
        self.inner.style()
    }

    /// Lays the C out in `style` from now on: the documents shown are
    /// printed again (an [`Event::Changed`] names them;
    /// [`binbun_session::Session::set_style`]).
    pub fn set_style(&self, style: Style) {
        self.inner.set_style(style);
    }

    /// Names the function or global at `address` `name` (`None`: its own
    /// name again).
    ///
    /// # Errors
    ///
    /// The session refuses it (no function there after all).
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the views hand over the name typed"
    )]
    pub fn rename(&mut self, address: u64, name: Option<String>) -> Result<(), String> {
        let function = self
            .database()
            .is_some_and(|db| db.function_at(address).is_some());
        self.as_user(|inner| {
            if function {
                inner
                    .rename_function(address, name.as_deref())
                    .map(drop)
                    .map_err(|error| error.to_string())
            } else {
                inner
                    .rename_global(address, name.as_deref())
                    .map(drop)
                    .map_err(|error| error.to_string())
            }
        })??;
        self.edited();
        Ok(())
    }

    /// Names variable `var` of `document`'s function `name` (`None`: its
    /// default again); a global the C prints is renamed as the listing
    /// renames it, everywhere it is used.
    ///
    /// # Errors
    ///
    /// The session refuses it (the function is not decompiled in that view).
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the views hand over the name typed"
    )]
    pub fn rename_variable(
        &mut self,
        document: &CDocument,
        var: VarId,
        name: Option<String>,
    ) -> Result<(), String> {
        self.as_user(|inner| {
            inner
                .rename_variable_in(document.function, document.view, var, name.as_deref())
                .map_err(|error| error.to_string())
        })??;
        self.edited();
        Ok(())
    }

    /// Comments `address` with `text` (`None`: no comment).
    ///
    /// # Errors
    ///
    /// The session refuses it (a share's project while joining, or a role
    /// that may not write it).
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the views hand over the text typed"
    )]
    pub fn comment(&mut self, address: u64, text: Option<String>) -> Result<(), String> {
        self.as_user(|inner| {
            inner
                .comment(address, text.as_deref())
                .map_err(|error| error.to_string())
        })??;
        self.edited();
        Ok(())
    }

    /// Bookmarks `address` as `name` (`None` or empty: no bookmark),
    /// undoably (`Alt+M`).
    pub fn bookmark(&mut self, address: u64, name: Option<String>) {
        let name = name.filter(|name| !name.is_empty());
        let before = self.overlay.bookmarks.get(&address).cloned();
        if before == name {
            return;
        }
        let made = self.as_user(|inner| {
            inner
                .bookmark(address, name.as_deref())
                .map_err(|error| error.to_string())
        });
        if let Err(why) = made.and_then(|made| made) {
            self.refuse(why);
            return;
        }
        self.edited();
    }

    /// Finds `matcher` in `listing`'s lines as shown (the user's names and
    /// comments laid over them, the prefix not searched) on threads of
    /// their own, chunk by chunk as `plan` orders them: each chunk's
    /// matches as it is searched ([`crate::search::Found`] takes them;
    /// [`binbun_session::Session::find_in_listing`]).
    pub fn find_in_listing(
        &self,
        listing: &Arc<Listing>,
        matcher: &Arc<Matcher>,
        plan: Plan,
    ) -> Search<Hit> {
        self.inner
            .find_in_listing(listing, matcher, plan, &self.wake)
    }

    /// Searches the whole listing (if built) and every function's C in
    /// `view` for `matcher` on threads of their own (`Alt+T`): the
    /// listing first, then the functions, each
    /// decompiled as it is reached if it is not yet
    /// ([`binbun_session::Session::search_text`]).
    pub fn search_text(
        &self,
        listing: Option<&Arc<Listing>>,
        view: View,
        matcher: &Arc<Matcher>,
    ) -> Search<TextHit> {
        self.inner
            .search_text(listing, Some(view), matcher, &self.wake)
    }

    /// Searches the listing's instructions for an operand that is `value`
    /// and every function's C in `view` for a literal that is (across
    /// widths: [`crate::search::is_immediate`]; `Alt+I`), as
    /// [`Self::search_text`] searches
    /// ([`binbun_session::Session::search_immediate`]).
    pub fn search_immediate(
        &self,
        listing: Option<&Arc<Listing>>,
        view: View,
        value: u64,
    ) -> Search<TextHit> {
        self.inner
            .search_immediate(listing, Some(view), value, &self.wake)
    }

    /// Searches the image's segments (or, `file`, the whole file) for
    /// `pattern` on threads of their own (`Alt+B`): each hit at its
    /// address (or file offset), with the bytes around it. `None` before
    /// the image is parsed ([`binbun_session::Session::search_bytes`]).
    pub fn search_bytes(&self, pattern: &Arc<BytePattern>, file: bool) -> Option<Search<ByteHit>> {
        self.inner.search_bytes(pattern, file, &self.wake)
    }

    /// Names the frame slot at `offset` (from the stack pointer on entry)
    /// of the function at `entry` `name` (`None`: its default again): the
    /// same edit as renaming the exact C's variable that is exactly that
    /// slot, where one is; else the slot's own name (the listing's).
    ///
    /// # Errors
    ///
    /// No function starts at `entry`, or it does not decompile.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the views hand over the name typed"
    )]
    pub fn rename_slot(
        &mut self,
        entry: u64,
        offset: i64,
        name: Option<String>,
    ) -> Result<(), String> {
        let error = |error: binbun_session::Error| error.to_string();
        let function = self
            .database()
            .and_then(|db| db.function_at(entry))
            .ok_or_else(|| format!("no function starts at {entry:#x}"))?;
        self.as_user(|inner| {
            match inner.slot_variable(function, offset).map_err(error)? {
                Some(var) => {
                    inner
                        .rename_variable_in(function, View::Exact, var, name.as_deref())
                        .map_err(error)?;
                }
                None => {
                    inner
                        .rename_slot(entry, offset, name.as_deref())
                        .map_err(error)?;
                }
            }
            Ok::<(), String>(())
        })??;
        self.edited();
        Ok(())
    }

    /// Writes the number `value` the instruction at `address` uses in
    /// `form` (`None`: as the listing and the printer choose), in place of
    /// its form at another width (one number at every width).
    pub fn number(&mut self, address: u64, value: u64, form: Option<NumberForm>) {
        let before = self.overlay.number(address, value);
        if before == form {
            return;
        }
        let made = self.as_user(|inner| {
            inner
                .number(address, value, form)
                .map_err(|error| error.to_string())
        });
        if let Err(why) = made.and_then(|made| made) {
            self.refuse(why);
            return;
        }
        self.edited();
    }

    /// Whether there is an edit to undo.
    pub fn can_undo(&self) -> bool {
        self.inner.can_undo()
    }

    /// The identity types attach to of variable `var` of `document`'s
    /// function.
    ///
    /// # Errors
    ///
    /// The session no longer has the function decompiled in that view.
    pub fn variable_typed(&self, document: &CDocument, var: VarId) -> Result<Typed, String> {
        self.inner
            .variable(document.function, document.view, var)
            .map(Typed::Variable)
            .map_err(|error| error.to_string())
    }

    /// The user's type of `typed`, as C.
    pub fn type_of(&self, typed: &Typed) -> Option<String> {
        self.inner.type_of(typed)
    }

    /// The names a type may be written with, sorted (completion).
    pub fn type_names(&self) -> Vec<String> {
        self.inner.type_names()
    }

    /// Why C `c` cannot type `typed`, with the bytes at fault; `None` if
    /// it can (or the functions are not recovered yet).
    pub fn check_type(&self, typed: &Typed, c: &str) -> Option<CError> {
        match self.inner.check_type(typed, c) {
            Err(binbun_session::Error::Type(error)) => Some(error),
            Ok(()) | Err(_) => None,
        }
    }

    /// Types `typed` as C `c` (`None`: as analysis types it again).
    ///
    /// # Errors
    ///
    /// The session refuses the C.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the views hand over the C typed"
    )]
    pub fn set_type(&mut self, typed: Typed, c: Option<String>) -> Result<(), String> {
        if self.inner.type_of(&typed) == c {
            return Ok(());
        }
        self.as_user(|inner| {
            inner
                .set_type(typed, c.as_deref())
                .map_err(|error| error.to_string())
        })??;
        self.edited();
        Ok(())
    }

    /// The user's definition of `key` (`struct pair`), as C.
    pub fn definition(&self, key: &str) -> Option<String> {
        self.inner.edits().definitions().get(key).cloned()
    }

    /// Defines what C `c` defines as the user's; the key it defined.
    ///
    /// # Errors
    ///
    /// The C is refused (the message, the bytes at fault).
    pub fn define(&mut self, c: &str) -> Result<String, CError> {
        let (key, _) = self
            .as_user(|inner| inner.define(c))
            .map_err(|message| CError {
                message,
                span: 0..0,
            })?
            .map_err(refused)?;
        self.edited();
        Ok(key)
    }

    /// Whether there is an undone edit to make again.
    pub fn can_redo(&self) -> bool {
        self.inner.can_redo()
    }

    /// The program's synthesised structs as the whole-program table found
    /// them last, `None` while none is known
    /// ([`binbun_session::Session::synthesised`]).
    pub fn synthesised(&self) -> Option<Arc<Vec<Synthesised>>> {
        self.inner.synthesised()
    }

    /// The global holding `address` typed over the whole program, with
    /// its declaration as the C prints it
    /// ([`binbun_session::Session::global_type`]).
    pub fn global_type(&self, address: u64) -> Option<GlobalTyped> {
        self.inner.global_type(address)
    }

    /// The name of the global starting at `start` as the C names it.
    pub fn global_name(&self, start: u64) -> String {
        self.inner.global_name(start)
    }

    /// The type of the global starting at `start` as a table of its own,
    /// its types named ([`binbun_session::Session::global_table`]).
    pub fn global_table(&self, start: u64) -> Option<GlobalTable> {
        self.inner.global_table(start)
    }

    /// The C definition of the struct or union `key` names: the user's,
    /// else the type library's.
    pub fn definition_text(&self, key: &str) -> Option<String> {
        self.inner.definition_text(key)
    }

    /// The keys the user's definitions define.
    pub fn definition_keys(&self) -> Vec<String> {
        self.inner.edits().definitions().keys().cloned().collect()
    }

    /// The struct or union `key` as C as the session has it: the user's,
    /// a synthesised struct's as the C prints it, the type library's.
    pub fn struct_c(&self, key: &str) -> Option<String> {
        self.inner.struct_c(key).map(|(_, c)| c)
    }

    /// Why C `c` (the struct or union `key` with its member `member`
    /// edited as `edit` says) does not hold, with the bytes at fault;
    /// `None` if it holds.
    pub fn check_member(
        &self,
        key: &str,
        member: &str,
        edit: &MemberEdit,
        c: &str,
    ) -> Option<CError> {
        self.inner
            .check_member(key, member, edit, c)
            .err()
            .map(refused)
    }

    /// Edits member `member` of the struct or union `key` as `edit` says,
    /// undoably, as the struct editor applies the struct (a synthesised
    /// struct's user's version, else the user's definition).
    ///
    /// # Errors
    ///
    /// The edit is refused (the C does not read, or the struct's layout
    /// would not hold).
    pub fn edit_member(
        &mut self,
        key: &str,
        member: &str,
        edit: &MemberEdit,
    ) -> Result<(), CError> {
        let c = self
            .inner
            .member_edited(key, member, edit)
            .map_err(refused)?;
        match self.inner.struct_c(key) {
            Some((Some(typed), _)) => self.set_type(typed, Some(c)).map_err(|message| CError {
                message,
                span: 0..0,
            }),
            Some((None, _)) | None => self.define(&c).map(|_| ()),
        }
    }

    /// The layout of the struct or union C `c` defines, nothing defined.
    ///
    /// # Errors
    ///
    /// The C is refused (the message, the bytes at fault), or the
    /// functions are not recovered yet (no bytes).
    pub fn struct_layout(&self, c: &str) -> Result<StructLayout, CError> {
        self.inner.struct_layout(c).map_err(refused)
    }

    /// The layout of the struct, union or enumeration C `c` defines,
    /// nothing defined (what the struct editor checks as it is typed).
    ///
    /// # Errors
    ///
    /// The C is refused (the message, the bytes at fault), or the
    /// functions are not recovered yet (no bytes).
    pub fn type_layout(&self, c: &str) -> Result<TypeLayout, CError> {
        self.inner.type_layout(c).map_err(refused)
    }

    /// The enumerations of `value` (the number as written): each name a
    /// number's form may give ([`NumberForm::Enum`]) with how the value
    /// reads by its constants (`GENERIC_READ | GENERIC_WRITE`), for those
    /// with a constant equal to it or flags it holds; sorted by name.
    pub fn enumerations_of(&self, written: Written) -> Vec<(String, String)> {
        self.inner
            .enumerations()
            .into_iter()
            .filter_map(|(name, enumeration)| {
                Some((name, by_name(&enumeration, written, Radix::Masm)?))
            })
            .collect()
    }

    /// Every enumeration's name a number's form may give, sorted.
    pub fn enumeration_names(&self) -> Vec<String> {
        self.inner
            .enumerations()
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    /// Takes C `c` as what `target` defines (undoably): a synthesised
    /// struct's user's version, else a definition (a definition renamed
    /// leaves its old key undefined). What it edits now.
    ///
    /// # Errors
    ///
    /// The C is refused (the message, the bytes at fault).
    pub fn apply_struct(&mut self, target: &StructTarget, c: &str) -> Result<StructTarget, CError> {
        if let &StructTarget::Synthesised { function, k } = target {
            let typed = Typed::Struct { function, k };
            if let Some(error) = self.check_type(&typed, c) {
                return Err(error);
            }
            self.set_type(typed, Some(c.trim().to_owned()))
                .map_err(|message| CError {
                    message,
                    span: 0..0,
                })?;
            return Ok(target.clone());
        }
        // A definition renamed is one undo step: the new key defined, the
        // old one undefined.
        let made = self
            .as_user(|inner| {
                inner.begin("Edit struct", Origin::User);
                let key = match inner.define(c) {
                    Ok((key, _)) => key,
                    Err(error) => {
                        inner.rollback();
                        return Err(refused(error));
                    }
                };
                if let StructTarget::Definition(old) = target
                    && *old != key
                    && inner.edits().definitions().contains_key(old)
                    && let Err(error) = inner.undefine(old)
                {
                    inner.rollback();
                    return Err(refused(error));
                }
                inner.commit().map(|_| key).map_err(refused)
            })
            .map_err(|message| CError {
                message,
                span: 0..0,
            })?;
        self.edited();
        Ok(StructTarget::Definition(made?))
    }

    /// Undoes the last edit (the session's journal: by compare-and-set),
    /// analysing the binary again if it was a correction.
    ///
    /// # Errors
    ///
    /// The session refuses the edit undoing it.
    pub fn undo(&mut self) -> Result<(), String> {
        self.as_user(|inner| inner.undo().map_err(|error| error.to_string()))??;
        self.edited();
        Ok(())
    }

    /// Makes the last undone edit again (as [`Self::undo`]).
    ///
    /// # Errors
    ///
    /// The session refuses it.
    pub fn redo(&mut self) -> Result<(), String> {
        self.as_user(|inner| inner.redo().map_err(|error| error.to_string()))??;
        self.edited();
        Ok(())
    }

    /// Saves the edits to the project file.
    ///
    /// # Errors
    ///
    /// It cannot be written.
    pub fn save(&self) -> Result<(), String> {
        self.inner.save().map_err(|error| error.to_string())
    }

    /// After an edit: the overlay at once (not when the change event
    /// comes), and the binary analysed again if the corrections changed.
    fn edited(&mut self) {
        self.overlay = self.inner.overlay();
        self.shelve();
        self.reanalyse();
    }

    /// The others' and the private bookmarks taken again.
    fn shelve(&mut self) {
        self.others = self.inner.others_bookmarks();
        self.private = self.inner.private_bookmarks();
    }

    // ---- others' and private bookmarks ----

    /// The others' bookmarks, by author (agents' too), never this
    /// identity's.
    pub fn others_bookmarks(&self) -> &Shelves {
        &self.others
    }

    /// This person's private bookmarks: kept here only, never sent.
    pub fn private_bookmarks(&self) -> &BTreeMap<u64, String> {
        &self.private
    }

    /// Bookmarks `address` privately as `name` (`None` or empty: none),
    /// undoably.
    ///
    /// # Errors
    ///
    /// The session refuses it.
    pub fn bookmark_private(&mut self, address: u64, name: Option<String>) -> Result<(), String> {
        let name = name.filter(|name| !name.is_empty());
        self.as_user(|inner| inner.bookmark_private(address, name.as_deref()))?
            .map_err(|error| error.to_string())?;
        self.edited();
        Ok(())
    }

    /// Makes this person's bookmark at `address` private (gone for the
    /// others), or shared again: one undo step.
    ///
    /// # Errors
    ///
    /// There is no such bookmark; the session refuses it.
    pub fn set_bookmark_private(&mut self, address: u64, private: bool) -> Result<(), String> {
        self.as_user(|inner| inner.set_bookmark_private(address, private))?
            .map_err(|error| error.to_string())?;
        self.edited();
        Ok(())
    }

    // ---- conversation ----

    /// This install's identity (the one signing its changes).
    pub fn identity(&self) -> PublicKey {
        self.inner.identity()
    }

    /// The agents this install signs for: each one's key and name.
    pub fn agents(&self) -> Vec<(PublicKey, String)> {
        self.inner.agents()
    }

    /// Agent `key`'s identity (its card is made of it when it joins a
    /// shared project), if this install signs for it.
    pub fn agent_identity(&self, key: PublicKey) -> Option<binbun_session::identity::Identity> {
        self.inner.agent_identity(key)
    }

    /// The change the next undo undoes, if any.
    pub fn next_undo(&self) -> Option<HistoryEntry> {
        self.inner.next_undo()
    }

    /// Whose key gave the function at `entry` the name it shows, if an
    /// edit did.
    pub fn name_writer(&self, entry: u64) -> Option<PublicKey> {
        self.inner.name_writer(entry)
    }

    /// Every thread, in the order opened.
    pub fn threads(&self) -> Vec<Thread> {
        self.inner.threads()
    }

    /// The threads about the function at `entry`.
    pub fn threads_of(&self, entry: u64) -> Vec<Thread> {
        self.inner.threads_of(entry)
    }

    /// Thread `id`, if made.
    pub fn thread(&self, id: OpId) -> Option<Thread> {
        self.inner.thread(id)
    }

    /// Where `anchor` is now, without decompiling anything (the UI never
    /// waits): as `binbun_session::Session::locate` finds it, a C line
    /// found in the document kept for its function and view (none kept:
    /// no line yet).
    pub fn locate(&self, anchor: &Anchor) -> Located {
        let function = |entry: u64| self.database().and_then(|db| db.function_at(entry));
        match anchor {
            Anchor::Function(entry) => {
                function(*entry).map_or(Located::Detached, Located::Function)
            }
            Anchor::Variable(variable) => {
                function(variable.function).map_or(Located::Detached, Located::Function)
            }
            Anchor::Line {
                function: entry,
                reading,
                address,
            } => {
                let Some(id) = function(*entry) else {
                    return Located::Detached;
                };
                let view = if *reading { View::Reading } else { View::Exact };
                let line = self
                    .document(id, view)
                    .and_then(|document| document.lines_of(*address).next());
                Located::Line {
                    function: id,
                    view,
                    line,
                }
            }
            Anchor::Instruction(address) | Anchor::Data(address) => {
                let held = self
                    .inner
                    .image()
                    .is_some_and(|image| image.segment(*address).is_some());
                if held {
                    Located::Address(*address)
                } else {
                    Located::Detached
                }
            }
            Anchor::Type(key) => Located::Type(key.clone()),
            Anchor::Suggestion(id) => {
                if self.inner.suggestion(*id).is_some() {
                    Located::Suggestion(*id)
                } else {
                    Located::Detached
                }
            }
        }
    }

    /// Opens a thread on `anchor`, quoting `quote`; its id.
    ///
    /// # Errors
    ///
    /// The session refuses it.
    pub fn open_thread(&self, anchor: Anchor, quote: &str) -> Result<OpId, String> {
        self.as_user(|inner| inner.open_thread(anchor, quote))?
            .map_err(|error| error.to_string())
    }

    /// Posts `say` in `thread`; its id.
    ///
    /// # Errors
    ///
    /// The session refuses it.
    pub fn post(&self, thread: OpId, say: Say) -> Result<OpId, String> {
        self.as_user(|inner| inner.post(thread, say))?
            .map_err(|error| error.to_string())
    }

    /// Edits this person's post `post` to say `body`.
    ///
    /// # Errors
    ///
    /// Another's, deleted; the session refuses it.
    pub fn edit_post(&self, post: OpId, body: &str) -> Result<(), String> {
        self.as_user(|inner| inner.edit_post(post, body))?
            .map_err(|error| error.to_string())
    }

    /// Deletes post `post` (one's own, or anyone's as the owner).
    ///
    /// # Errors
    ///
    /// Another's and this person no owner; the session refuses it.
    pub fn delete_post(&self, post: OpId) -> Result<(), String> {
        self.as_user(|inner| inner.delete_post(post))?
            .map_err(|error| error.to_string())
    }

    /// Resolves `thread`, or opens it again.
    ///
    /// # Errors
    ///
    /// The session refuses it.
    pub fn resolve_thread(&self, thread: OpId, resolved: bool) -> Result<(), String> {
        self.as_user(|inner| inner.resolve_thread(thread, resolved))?
            .map_err(|error| error.to_string())
    }

    /// Every suggestion, in the order made.
    pub fn suggestions(&self) -> Vec<Suggestion> {
        self.inner.suggestions()
    }

    /// The suggestions waiting for review.
    pub fn pending_suggestions(&self) -> Vec<Suggestion> {
        self.inner.pending_suggestions()
    }

    /// Suggestion `id`, if made.
    pub fn suggestion(&self, id: OpId) -> Option<Suggestion> {
        self.inner.suggestion(id)
    }

    /// Accepts suggestion `id`'s edits `chosen` (by number, at least
    /// one): one undo step, the history saying who suggested it.
    ///
    /// # Errors
    ///
    /// Nothing chosen; the session refuses it.
    pub fn accept(&mut self, id: OpId, chosen: &[usize]) -> Result<(), String> {
        if chosen.is_empty() {
            return Err("no edit chosen".to_owned());
        }
        self.as_user(|inner| inner.accept(id, chosen))?
            .map_err(|error| error.to_string())?;
        self.edited();
        Ok(())
    }

    /// Dismisses suggestion `id`, saying why.
    ///
    /// # Errors
    ///
    /// The session refuses it.
    pub fn dismiss(&self, id: OpId, reason: &str) -> Result<(), String> {
        self.as_user(|inner| inner.dismiss(id, reason))?
            .map_err(|error| error.to_string())
    }

    /// Asks suggestion `id`'s evidence again on a thread of its own (the
    /// answers anew, never kept ones): [`Event::Rechecked`] when done.
    pub fn recheck(&self, id: OpId) {
        let Some(suggestion) = self.inner.suggestion(id) else {
            return;
        };
        let core = Arc::clone(&self.inner);
        let sender = self.sender.clone();
        let wake = Arc::clone(&self.wake);
        let _ = thread::Builder::new()
            .name("binbun-recheck".to_owned())
            .spawn(move || {
                let items = core.recheck(&suggestion.evidence, Some(RECHECK));
                let _ = sender.send(Event::Rechecked {
                    suggestion: id,
                    items: items.into(),
                });
                wake();
            });
    }

    /// The changes, newest first: every author's.
    pub fn history(&self) -> Vec<HistoryEntry> {
        self.inner.history()
    }
}

/// A refusal of C as the parser's error: its own, else the session's
/// reason with no bytes at fault.
fn refused(error: binbun_session::Error) -> CError {
    use binbun_session::Error as E;
    match error {
        E::Type(error) => error,
        other @ (E::Project(_)
        | E::NoFunction(_)
        | E::NotDecompiled(_)
        | E::NoVariable(_)
        | E::NotAnalysed
        | E::Correction(_)
        | E::Transaction(_)
        | E::Conversation(_)
        | E::Refused(_)) => CError {
            message: other.to_string(),
            span: 0..0,
        },
    }
}

/// The pump: the lineage's events as [`Event`]s, until it is gone (a
/// swap told as [`Event::Reopened`], after what the session replaced
/// told).
fn pump(
    session: &Weak<Lineage>,
    received: &Receiver<SessionEvent>,
    sender: &Sender<Event>,
    wake: &Wake,
    wanted: &Arc<Mutex<Wanted>>,
) {
    for event in received {
        let event = match event {
            SessionEvent::Stage(stage) => {
                // Once per session, at the first stage told this far: one
                // subscribed late hears the stage it reached, past these.
                let (listing, strings) = {
                    let mut wanted = wanted.lock().unwrap_or_else(PoisonError::into_inner);
                    let listing = (stage >= Stage::Analysed && !wanted.analysed)
                        .then(|| wanted.listing.clone());
                    wanted.analysed |= stage >= Stage::Analysed;
                    let strings = stage >= Stage::Referenced && !wanted.referenced;
                    wanted.referenced |= strings;
                    (listing, strings)
                };
                // The stage told before the listing and the strings it
                // starts, which come from threads of their own.
                if sender.send(Event::Stage(stage)).is_err() {
                    return;
                }
                wake();
                if let Some(options) = listing {
                    build_listing(
                        Weak::clone(session),
                        options,
                        sender.clone(),
                        Arc::clone(wake),
                    );
                }
                if strings {
                    find_strings(Weak::clone(session), sender.clone(), Arc::clone(wake));
                }
                continue;
            }
            SessionEvent::Progress { .. } => continue,
            SessionEvent::Thread(talked) => Event::Talked(talked),
            SessionEvent::Mentioned(mentioned) => Event::Mentioned(mentioned),
            SessionEvent::Bookmarks => Event::Bookmarks,
            SessionEvent::History(entries) => Event::History(entries),
            SessionEvent::Conflicts(conflicts) => Event::Conflicts(conflicts),
            SessionEvent::Reanalysed { functions, .. } => {
                // Requests are numbered anew in the new session, whose
                // listing and strings come once its stages are told.
                let mut wanted = wanted.lock().unwrap_or_else(PoisonError::into_inner);
                wanted.views.clear();
                wanted.analysed = false;
                wanted.referenced = false;
                Event::Reopened(functions)
            }
            SessionEvent::Changed(change) => Event::Changed(change),
            SessionEvent::Document {
                request,
                function,
                result,
            } => {
                let asked = wanted
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .views
                    .remove(&request);
                let view = match &result {
                    Ok(document) => document.view,
                    Err(_) => asked.unwrap_or_default(),
                };
                Event::Document {
                    function,
                    view,
                    result: result.map(|document| Arc::new(CDocument::new(&document))),
                }
            }
            SessionEvent::Unresolved(unresolved) => Event::Failed(
                unresolved
                    .iter()
                    .map(|u| format!("{}: {}", u.edit, u.why))
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
            SessionEvent::Failed(message) => Event::Failed(message),
            SessionEvent::Symbols(state) => Event::Symbols(state),
            SessionEvent::Answer {
                request,
                function,
                view,
                answer,
            } => Event::Answer {
                request,
                function,
                view,
                answer,
            },
        };
        if sender.send(event).is_err() {
            return;
        }
        wake();
    }
}

/// Has the session build the listing under `options` on a thread of its
/// own ([`binbun_session::Session::listing`]).
fn build_listing(
    session: Weak<Lineage>,
    options: ListingOptions,
    sender: Sender<Event>,
    wake: Wake,
) {
    let _ = thread::Builder::new()
        .name("binbun-gui-listing".to_owned())
        .spawn(move || {
            let Some(session) = session.upgrade().map(|lineage| lineage.session()) else {
                return;
            };
            let Some(listing) = session.listing(&options) else {
                return;
            };
            if sender.send(Event::Listing(listing)).is_ok() {
                wake();
            }
        });
}

/// The shortest string literal found by scanning.
const MIN_STRING: usize = 5;

/// Finds the strings on a thread of its own.
fn find_strings(session: Weak<Lineage>, sender: Sender<Event>, wake: Wake) {
    let _ = thread::Builder::new()
        .name("binbun-gui-strings".to_owned())
        .spawn(move || {
            let Some(session) = session.upgrade().map(|lineage| lineage.session()) else {
                return;
            };
            let Some(db) = session.database() else {
                return;
            };
            let strings = db
                .strings(MIN_STRING)
                .into_iter()
                .map(|literal| StringItem {
                    address: literal.address,
                    size: literal.bytes,
                    wide: literal.encoding == Encoding::Utf16,
                    text: literal.text,
                })
                .collect();
            if sender.send(Event::Strings(Arc::new(strings))).is_ok() {
                wake();
            }
        });
}

/// The status bar's words for the analysis running after `stage`
/// (`again`: a correction's, beside the one shown), with how far its
/// whole-program pass has got ([`Session::progress`]) where that pass is
/// the stage's own: `Reading callers 1,234 / 5,678`. The stages between
/// (naming library functions, warming) count nothing, and the last pass's
/// count would read as theirs.
pub fn analysis_label(stage: Stage, again: bool, progress: Option<(usize, usize)>) -> String {
    let (word, counted) = if again {
        ("Analysing again", false)
    } else {
        match stage {
            Stage::Opening => ("Opening", false),
            Stage::Image => ("Finding functions", false),
            Stage::Analysed => ("Finding references", true),
            Stage::Referenced => ("Naming library functions", false),
            Stage::Signatures => ("Reading callers", true),
            Stage::Callers | Stage::Warmed => ("Analysing", false),
        }
    };
    match progress.filter(|_| counted) {
        Some((done, total)) => format!("{word} {} / {}", grouped(done), grouped(total)),
        None => word.to_owned(),
    }
}

/// `n` in digits grouped in threes (`12,345`).
fn grouped(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::ops::Range;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use binbun_session::Edits;
    use binbun_session::number::parse;

    use super::{Event, Session, Stage, View, analysis_label, grouped, without_signatures};
    use crate::FunctionId;
    use crate::cdoc::CDocument;
    use crate::comment::CommentField;
    use crate::listing::{LineKind, Listing, Options as ListingOptions, Role};
    use crate::search::{
        Batch, ByteHit, ByteMode, BytePattern, CONTEXT, Found, Matcher, Plan, Query, Search,
        Source, TextHit, is_immediate, listing_text,
    };
    use crate::settings::SymbolDownload;

    /// `tests/fixtures/{name}`.
    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    /// The label counts only the passes of the stage running, with the
    /// digits grouped; the stages in between say only their name.
    #[test]
    fn the_analysis_label_counts_the_running_stages_pass() {
        assert_eq!(
            analysis_label(Stage::Signatures, false, Some((1234, 56_789))),
            "Reading callers 1,234 / 56,789"
        );
        assert_eq!(
            analysis_label(Stage::Analysed, false, Some((7, 1797))),
            "Finding references 7 / 1,797"
        );
        // The references' last count while the signatures run.
        assert_eq!(
            analysis_label(Stage::Referenced, false, Some((1797, 1797))),
            "Naming library functions"
        );
        assert_eq!(
            analysis_label(Stage::Image, false, None),
            "Finding functions"
        );
        assert_eq!(
            analysis_label(Stage::Signatures, true, Some((1, 2))),
            "Analysing again"
        );
        for (n, text) in [
            (0, "0"),
            (999, "999"),
            (1000, "1,000"),
            (1_234_567, "1,234,567"),
        ] {
            assert_eq!(grouped(n), text);
        }
    }

    #[test]
    fn the_symbols_bar_goes_once_the_session_in_use_has_debug_information() {
        use binbun_debuginfo::symbols::{Config, Identity, Server};
        use binbun_session::{Download, Symbols};

        use crate::symbols::Bar;
        use crate::test_server::LocalServer;

        let dir = std::env::temp_dir().join(format!("binbun-gui-debugged-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // The binary alone (its debug file not beside it), offered by a
        // local debuginfod.
        let binary = dir.join("units-x86_64.elf");
        std::fs::copy(fixture("units-x86_64.elf"), &binary).unwrap();
        let identity = Identity::of(&std::fs::read(&binary).unwrap()).unwrap();
        let (url, _) = identity.urls("").remove(0);
        let debug = std::fs::read(fixture("units-x86_64.debug")).unwrap();
        let server = LocalServer::serve(vec![(url, debug)]);
        let cache = dir.join("cache");
        let symbols = Symbols {
            download: Download::Ask,
            config: Config {
                stores: vec![cache.clone()],
                pdb_servers: Vec::new(),
                debuginfod: vec![Server::new(&server.url, &cache)],
                timeout: Duration::from_secs(5),
            },
        };
        let mut session = Session::open_with(
            binary,
            None,
            None,
            Some(&dir),
            ListingOptions::default(),
            symbols,
            without_signatures(),
            Arc::new(|| {}),
        )
        .unwrap();
        poll_until(&mut session, |e| matches!(e, Event::Symbols(_)));
        assert!(
            matches!(session.symbols_bar(), Some(Bar::Offer { .. })),
            "{:?}",
            session.symbols_bar()
        );
        // A peer's copy of the debug file taken: analysed again with it,
        // swapped in. The offer, told for the session before, goes.
        session.analyse_with_debug(fixture("units-x86_64.debug"));
        poll_until(&mut session, |e| matches!(e, Event::Reopened(_)));
        assert!(session.inner.debug_file().is_some());
        assert_eq!(session.symbols_bar(), None);
        // And stays away; nothing was asked of the server.
        session.poll();
        assert_eq!(session.symbols_bar(), None);
        assert_eq!(server.requests(), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Polls `session` until `done` holds of an event; the events polled.
    fn poll_until(session: &mut Session, done: impl Fn(&Event) -> bool) -> Vec<Event> {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut seen = Vec::new();
        loop {
            let events = session.poll();
            let found = events.iter().any(&done);
            seen.extend(events);
            if found {
                return seen;
            }
            assert!(Instant::now() < deadline, "timed out: {seen:?}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_session_analysed_before_it_is_shown_builds_its_listing_and_finds_its_strings() {
        use binbun_session::{Lineage, Options};
        let dir = std::env::temp_dir().join(format!("binbun-gui-late-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lineage = Lineage::open(
            fixture("program-x86_64.elf"),
            Options {
                projects: Some(dir.join("projects")),
                identity: Some(dir.join("identity")),
                signatures: without_signatures(),
                ..Options::default()
            },
        )
        .unwrap();
        // Waited for on the lineage, which relays the session's stages a
        // little behind it: a subscriber's first stage is the relayed one.
        let relayed = lineage.subscribe(None);
        while !matches!(
            relayed.recv_timeout(Duration::from_secs(60)),
            Ok(binbun_session::Event::Stage(s)) if s >= Stage::Callers
        ) {}
        drop(relayed);
        // Its first stage told is past `Analysed` and `Referenced`.
        let mut session = Session::of_lineage(
            Arc::new(lineage),
            None,
            ListingOptions::default(),
            Arc::new(|| {}),
        )
        .unwrap();
        let listed = |e: &Event| matches!(e, Event::Listing(l) if l.function_of(0x11b0).is_some());
        let found = |e: &Event| matches!(e, Event::Strings(strings) if strings.iter().any(|s| s.text == "negative"));
        let mut events = poll_until(&mut session, |e| listed(e) || found(e));
        if !events.iter().any(listed) {
            events.extend(poll_until(&mut session, listed));
        }
        if !events.iter().any(found) {
            events.extend(poll_until(&mut session, found));
        }
        assert!(
            matches!(events.first(), Some(Event::Stage(s)) if *s >= Stage::Callers),
            "{events:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_correction_analyses_again_keeps_documents_by_entry_and_undoes() {
        use binbun::corrections::{Bounds, Corrections};
        let dir = std::env::temp_dir().join(format!("binbun-gui-correct-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("program");
        std::fs::copy(fixture("program-x86_64.elf"), &binary).unwrap();
        let mut session = Session::open_in(
            binary,
            Some(&dir),
            ListingOptions::default(),
            SymbolDownload::Never,
            Arc::new(|| {}),
        )
        .unwrap();
        poll_until(
            &mut session,
            |e| matches!(e, Event::Stage(s) if *s >= Stage::Analysed),
        );
        let database = session.database().unwrap();
        let fail = database.function_at(0x11b0).unwrap();
        assert!(session.ensure(fail, View::Exact));
        poll_until(
            &mut session,
            |e| matches!(e, Event::Document { function, .. } if *function == fail),
        );

        // `P` in `classify`'s padding: a function before `fail`.
        let mut made = Corrections::default();
        made.set_bounds(0x11a3, Some(Bounds::Function { end: None }));
        session.correct(made).unwrap();
        let events = poll_until(&mut session, |e| matches!(e, Event::Reopened(_)));
        let Some(Event::Reopened(functions)) =
            events.iter().find(|e| matches!(e, Event::Reopened(_)))
        else {
            unreachable!()
        };
        let database = session.database().unwrap();
        assert!(database.function_at(0x11a3).is_some());
        // `fail` is the function after the new one now; its document came
        // along, stale until its new one comes.
        let now = database.function_at(0x11b0).unwrap();
        assert_eq!(functions.get(&fail), Some(&now));
        assert_ne!(now, fail);
        let kept = session.document(now, View::Exact).unwrap();
        assert_eq!((kept.function, kept.entry), (now, 0x11b0));
        // A listing of the program analysed again (it may come with the
        // swap).
        let rebuilt = |e: &Event| matches!(e, Event::Listing(l) if l.function_of(0x11a3).is_some());
        if !events.iter().any(rebuilt) {
            poll_until(&mut session, rebuilt);
        }

        session.undo().unwrap();
        poll_until(&mut session, |e| matches!(e, Event::Reopened(_)));
        assert!(session.database().unwrap().function_at(0x11a3).is_none());
        assert!(session.corrections().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_correction_wakes_an_idle_front_end_once_it_can_be_shown() {
        use binbun::corrections::{Bounds, Corrections};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = std::env::temp_dir().join(format!("binbun-gui-woken-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("program");
        std::fs::copy(fixture("program-x86_64.elf"), &binary).unwrap();
        let woken = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&woken);
        let mut session = Session::open_in(
            binary,
            Some(&dir),
            ListingOptions::default(),
            SymbolDownload::Never,
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .unwrap();
        poll_until(&mut session, |e| matches!(e, Event::Stage(Stage::Warmed)));
        // Delete Function on the function at 0x1190. From here the front
        // end is idle, polling only when woken (as the GUI does): a poll
        // the change's own wake brings may already swap the new analysis
        // in, if it was quick; otherwise something must wake it once it
        // can be shown.
        let mut deleted = Corrections::default();
        deleted.set_bounds(0x1190, Some(Bounds::Deleted));
        let mut seen = woken.load(Ordering::SeqCst);
        session.correct(deleted).unwrap();
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            while woken.load(Ordering::SeqCst) == seen {
                assert!(Instant::now() < deadline, "never woken to show it");
                std::thread::sleep(Duration::from_millis(10));
            }
            seen = woken.load(Ordering::SeqCst);
            if session
                .poll()
                .iter()
                .any(|e| matches!(e, Event::Reopened(_)))
            {
                break;
            }
        }
        assert!(session.database().unwrap().function_at(0x1190).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_document_that_fails_is_asked_for_once_until_a_change_names_it() {
        use binbun_semantics::core::Id as _;
        let dir = std::env::temp_dir().join(format!("binbun-gui-failed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("program");
        std::fs::copy(fixture("program-x86_64.elf"), &binary).unwrap();
        let mut session = Session::open_in(
            binary,
            Some(&dir),
            ListingOptions::default(),
            SymbolDownload::Never,
            Arc::new(|| {}),
        )
        .unwrap();
        poll_until(
            &mut session,
            |e| matches!(e, Event::Stage(s) if *s >= Stage::Analysed),
        );
        // No such function: its document fails, as one the printer
        // cannot print does.
        let none = FunctionId::from_raw(u32::MAX - 1);
        let failed = |e: &Event| matches!(e, Event::Document { function, result: Err(_), .. } if *function == none);
        assert!(session.ensure(none, View::Exact));
        poll_until(&mut session, failed);
        assert_eq!(
            session.failure(none, View::Exact),
            Some("not a function of the program")
        );
        // Asked for again on every frame before: not now.
        assert!(!session.ensure(none, View::Exact));
        assert!(!session.is_pending(none, View::Exact));
        // The other view is its own.
        assert_eq!(session.failure(none, View::Reading), None);

        // A change naming it (as an edit's does) may make it print: asked
        // for again, once.
        let change = binbun_session::Change {
            documents: vec![none],
            listing: Vec::new(),
        };
        session
            .sender
            .send(Event::Changed(Arc::new(change)))
            .unwrap();
        poll_until(&mut session, |e| matches!(e, Event::Changed(_)));
        assert_eq!(session.failure(none, View::Exact), None);
        assert!(session.ensure(none, View::Exact));
        assert!(!session.ensure(none, View::Exact));
        poll_until(&mut session, failed);
        assert!(!session.ensure(none, View::Exact));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Comments `address` with `text`, the change heard.
    fn comment(session: &mut Session, address: u64, text: Option<String>) {
        session.comment(address, text).unwrap();
        poll_until(session, |e| matches!(e, Event::Changed(_)));
    }

    /// `function`'s exact document printed anew (asked for, polled).
    fn printed(session: &mut Session, function: FunctionId) -> Arc<CDocument> {
        session.ensure(function, View::Exact);
        poll_until(
            session,
            |e| matches!(e, Event::Document { function: f, result: Ok(_), .. } if *f == function),
        );
        Arc::clone(session.document(function, View::Exact).unwrap())
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one comment typed in each view, then removed"
    )]
    fn a_comment_typed_in_either_view_shows_in_the_other() {
        let dir = std::env::temp_dir().join(format!("binbun-gui-comments-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("program-x86_64.elf");
        std::fs::copy(fixture("program-x86_64.elf"), &binary).unwrap();
        let mut session = Session::open_in(
            binary,
            Some(&dir),
            ListingOptions::default(),
            SymbolDownload::Never,
            Arc::new(|| {}),
        )
        .unwrap();
        let events = poll_until(&mut session, |e| matches!(e, Event::Listing(_)));
        let built = events
            .into_iter()
            .find_map(|e| match e {
                Event::Listing(listing) => Some(listing),
                Event::Stage(_)
                | Event::Strings(_)
                | Event::Document { .. }
                | Event::Changed(_)
                | Event::Failed(_)
                | Event::Symbols(_)
                | Event::Answer { .. }
                | Event::Reopened(_)
                | Event::History(_)
                | Event::Conflicts(_)
                | Event::Talked(_)
                | Event::Mentioned(_)
                | Event::Bookmarks
                | Event::Rechecked { .. } => None,
            })
            .unwrap();
        let sum = session
            .database()
            .unwrap()
            .find_function("loop_sum")
            .unwrap();
        let doc = printed(&mut session, sum);
        // Two lines made from instructions none of which is the other's.
        let mut made = (0..doc.lines.len()).filter_map(|n| {
            let address = doc.comment_address(n)?;
            (doc.lines_of(address).next() == Some(n)).then_some((n, address))
        });
        let (c_line, c_address) = made.next().unwrap();
        let (l_line, l_address) = made.next().unwrap();
        let bare = doc.line_text(c_line).to_owned();

        // Typed on a C line: at its first instruction, shown on it, and on
        // that instruction's line of the listing.
        let mut field = CommentField::in_c(&doc, c_line, &session.overlay().comments).unwrap();
        assert_eq!(field.address, c_address);
        field.text = "from the C".to_owned();
        comment(&mut session, field.address, field.commit().unwrap());
        let doc = printed(&mut session, sum);
        assert_eq!(doc.line_text(c_line), format!("{bare} // from the C"));
        assert_eq!(doc.code_end(c_line), bare.len());
        let mut listing = (*built).clone();
        let overlay = session.overlay().clone();
        assert!(!listing.set_comments(&overlay.comments));
        let shown = listing
            .render(
                session.database().unwrap(),
                listing.line_of(c_address),
                &overlay,
            )
            .text();
        assert!(shown.ends_with("; from the C"), "{shown}");

        // Typed in the listing, two lines: its item's line and a comment
        // line under it at the same column; in the C, on the first line
        // made from the instruction, the second line under the first.
        let (address, first, column) = listing
            .comment_place(
                session.database().unwrap(),
                listing.line_of(l_address),
                &overlay,
            )
            .unwrap();
        assert_eq!(address, l_address);
        let mut field = CommentField::open(address, &overlay.comments);
        field.text = "from the\nlisting".to_owned();
        comment(&mut session, address, field.commit().unwrap());
        let overlay = session.overlay().clone();
        assert!(listing.set_comments(&overlay.comments));
        assert_eq!(listing.comment_lines(first), first..first + 2);
        let shown: Vec<String> = (first..first + 2)
            .map(|n| {
                listing
                    .render(session.database().unwrap(), n, &overlay)
                    .text()
            })
            .collect();
        for (line, piece) in shown.iter().zip(["; from the", "; listing"]) {
            let from = line.char_indices().nth(column).map(|(i, _)| &line[i..]);
            assert_eq!(from, Some(piece), "{shown:?}");
        }
        let doc = printed(&mut session, sum);
        let line = doc.lines_of(l_address).next().unwrap();
        assert_eq!(line, l_line);
        let below = doc.line_text(line + 1);
        assert!(
            doc.line_text(line).ends_with(" // from the"),
            "{}",
            doc.text
        );
        let indent = doc.line_text(line).find("// from").unwrap();
        assert_eq!(below, format!("{}// listing", " ".repeat(indent)));
        assert_eq!(doc.comment_lines(line + 1), line..line + 2);
        // Removed from the C's further line: gone from both.
        let mut field = CommentField::in_c(&doc, line + 1, &overlay.comments).unwrap();
        assert_eq!(field.address, l_address);
        field.text.clear();
        comment(&mut session, field.address, field.commit().unwrap());
        assert!(listing.set_comments(&session.overlay().comments));
        assert_eq!(listing.len(), built.len());
        let doc = printed(&mut session, sum);
        assert!(!doc.text.contains("listing"), "{}", doc.text);
        drop(session);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every result of `search`, once it is done.
    fn drain<T: Send + 'static>(mut search: Search<T>) -> Vec<Batch<T>> {
        let deadline = Instant::now() + Duration::from_secs(300);
        let mut out = Vec::new();
        while !search.is_done() {
            out.extend(search.poll());
            assert!(search.is_done() || search.is_running(), "stopped");
            assert!(Instant::now() < deadline, "timed out");
            std::thread::sleep(Duration::from_millis(5));
        }
        out.extend(search.poll());
        out
    }

    /// A session on the fixture with its project in a directory of its
    /// own (`name`), its listing built.
    fn fixture_session(name: &str) -> (Session, Arc<Listing>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("binbun-gui-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut session = Session::open_in(
            fixture("program-x86_64.elf"),
            Some(&dir),
            ListingOptions::default(),
            SymbolDownload::Never,
            Arc::new(|| {}),
        )
        .unwrap();
        let events = poll_until(&mut session, |e| matches!(e, Event::Listing(_)));
        let listing = events
            .into_iter()
            .find_map(|e| {
                if let Event::Listing(listing) = e {
                    Some(listing)
                } else {
                    None
                }
            })
            .unwrap();
        (session, listing, dir)
    }

    #[test]
    fn finding_in_the_listing_streams_what_a_scan_of_every_line_finds() {
        let (session, listing, dir) = fixture_session("find");
        let db = session.database().unwrap();
        let matcher = Arc::new(
            Matcher::new(&Query {
                text: "LOOP_SUM".to_owned(),
                ..Query::default()
            })
            .unwrap()
            .unwrap(),
        );
        // What every line as shown holds, past its prefix.
        let mut expected = Vec::new();
        for n in 0..listing.len() {
            let (text, start) = listing_text(&listing.render(db, n, session.overlay()));
            let lower = text.to_lowercase();
            let mut from = start;
            while let Some(at) = lower.get(from..).and_then(|rest| rest.find("loop_sum")) {
                expected.push((n, from + at));
                from += at + "loop_sum".len();
            }
        }
        assert!(expected.len() > 2, "{expected:?}");
        // Small chunks, from the middle: several segments, wrapping.
        let origin = listing.len() / 2;
        let plan = Plan::new(listing.len(), 64, origin);
        let mut found = Found::new(plan);
        let mut revealed = Vec::new();
        for batch in drain(session.find_in_listing(&listing, &matcher, plan)) {
            revealed.extend(found.add(batch.segment, batch.items));
        }
        assert!(found.is_complete());
        let got: Vec<(u64, usize)> = found.hits().iter().map(|h| (h.line, h.start)).collect();
        assert_eq!(got, expected);
        // Revealed once: the first from the middle on, else the first.
        let first = expected
            .iter()
            .find(|&&(n, _)| n >= origin)
            .or(expected.first())
            .copied();
        assert_eq!(
            revealed
                .iter()
                .map(|h| (h.line, h.start))
                .collect::<Vec<_>>(),
            first.into_iter().collect::<Vec<_>>()
        );
        drop(session);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn searching_everywhere_finds_listing_lines_and_every_functions_c() {
        let (session, listing, dir) = fixture_session("everywhere");
        let db = session.database().unwrap();
        let entry = |name: &str| {
            db.functions()
                .find(|(_, f)| db.name(f.entry) == Some(name))
                .map(|(_, f)| f.entry)
                .unwrap()
        };
        let (classify, checked) = (entry("classify"), entry("checked"));
        let matcher = Arc::new(
            Matcher::new(&Query {
                text: "classify".to_owned(),
                case: true,
                regex: false,
            })
            .unwrap()
            .unwrap(),
        );
        let hits: Vec<TextHit> = drain(session.search_text(Some(&listing), View::Exact, &matcher))
            .into_iter()
            .flat_map(|b| b.items)
            .collect();
        // Each hit's ranges are the word, in its text.
        for hit in &hits {
            assert_ne!(hit.ranges, Vec::<Range<usize>>::new());
            for r in &hit.ranges {
                assert_eq!(hit.text.get(r.clone()), Some("classify"), "{hit:?}");
            }
        }
        // The call in the listing, in `checked`.
        assert!(
            hits.iter().any(|h| h.source == Source::Listing
                && h.function == Some(checked)
                && h.text.starts_with("call")),
            "{hits:?}"
        );
        // The call in `checked`'s C, at an instruction of it, and the
        // prototype in `classify`'s own.
        assert!(
            hits.iter().any(|h| h.source == Source::C
                && h.function == Some(checked)
                && h.address != checked
                && h.text.contains("classify(")),
            "{hits:?}"
        );
        assert!(
            hits.iter()
                .any(|h| h.source == Source::C && h.function == Some(classify)),
            "{hits:?}"
        );
        drop(session);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn immediates_and_bytes_are_found_where_the_listing_shows_them() {
        let (session, listing, dir) = fixture_session("immediates");
        let db = session.database().unwrap();
        // The first instruction with a number operand, and that number.
        let (address, value) = (0..listing.len())
            .find_map(|n| {
                let line = listing.line(n)?;
                if line.kind != LineKind::Instruction {
                    return None;
                }
                let rendered = listing.render(db, n, session.overlay());
                rendered
                    .tokens
                    .iter()
                    .filter(|t| t.role == Role::Number)
                    .find_map(|t| parse(&t.text))
                    .map(|w| (line.address, w.bits))
            })
            .unwrap();
        let hits: Vec<TextHit> =
            drain(session.search_immediate(Some(&listing), View::Exact, value))
                .into_iter()
                .flat_map(|b| b.items)
                .collect();
        assert!(
            hits.iter()
                .any(|h| h.source == Source::Listing && h.address == address),
            "{value:#x}: {hits:?}"
        );
        for hit in &hits {
            for r in &hit.ranges {
                let text = hit.text.get(r.clone()).unwrap();
                let written = parse(&text.replace(' ', "")).unwrap();
                assert!(is_immediate(written.bits, value), "{text} in {hit:?}");
            }
        }
        // A number on a further line of a data item (one of its pieces):
        // found at that line's own address, as it shows it, not its
        // item's.
        let (piece, value) = (0..listing.len())
            .find_map(|n| {
                let line = listing.line(n)?;
                if line.kind != LineKind::Data {
                    return None;
                }
                let rendered = listing.render(db, n, session.overlay());
                let shown = rendered
                    .tokens
                    .first()
                    .filter(|t| t.role == Role::Prefix)?
                    .target?;
                if shown == line.address {
                    return None;
                }
                rendered
                    .tokens
                    .iter()
                    .filter(|t| t.role == Role::Number)
                    .find_map(|t| parse(&t.text))
                    .map(|w| (shown, w.bits))
            })
            .unwrap();
        let pieces: Vec<u64> = drain(session.search_immediate(Some(&listing), View::Exact, value))
            .into_iter()
            .flat_map(|b| b.items)
            .filter(|h| h.source == Source::Listing)
            .map(|h| h.address)
            .collect();
        assert!(pieces.contains(&piece), "{piece:#x}: {pieces:x?}");

        // The instruction's bytes, its second a wildcard: found at it,
        // as an address and as a file offset.
        let (bytes, image) = session.loaded().unwrap();
        let segment = image
            .segments
            .iter()
            .find(|s| (s.start..s.start + s.bytes.len() as u64).contains(&address))
            .unwrap();
        let at = usize::try_from(address - segment.start).unwrap();
        let code = &segment.bytes[at..at + 4];
        let text = format!("{:02X} ?? {:02x}{:X}?", code[0], code[2], code[3] >> 4);
        let pattern = Arc::new(BytePattern::parse(&text, ByteMode::Hex, false).unwrap());
        let found: Vec<ByteHit> = drain(session.search_bytes(&pattern, false).unwrap())
            .into_iter()
            .flat_map(|b| b.items)
            .collect();
        let hit = found.iter().find(|h| h.at == address).unwrap();
        assert_eq!(hit.bytes, code);
        assert_eq!(hit.before.len(), at.min(CONTEXT));
        let offset = bytes
            .windows(segment.bytes.len())
            .position(|w| w == segment.bytes)
            .unwrap()
            + at;
        let in_file: Vec<u64> = drain(session.search_bytes(&pattern, true).unwrap())
            .into_iter()
            .flat_map(|b| b.items)
            .map(|h| h.at)
            .collect();
        assert!(
            in_file.contains(&(offset as u64)),
            "{offset:#x}: {in_file:x?}"
        );
        drop(session);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bookmark_is_saved_undone_and_made_again() {
        let (mut session, _, dir) = fixture_session("bookmark");
        let entry = session
            .database()
            .unwrap()
            .functions()
            .next()
            .unwrap()
            .1
            .entry;
        session.bookmark(entry, Some("start here".to_owned()));
        assert_eq!(
            session.overlay().bookmarks.get(&entry).map(String::as_str),
            Some("start here")
        );
        session.save().unwrap();
        let saved = Edits::load(&session.project().unwrap().edits()).unwrap();
        assert_eq!(saved.bookmark(entry), Some("start here"));
        // Renamed, then undone back to the first name, then removed.
        session.bookmark(entry, Some("renamed".to_owned()));
        session.undo().unwrap();
        assert_eq!(session.inner.edits().bookmark(entry), Some("start here"));
        session.undo().unwrap();
        assert_eq!(session.inner.edits().bookmark(entry), None);
        assert!(session.overlay().bookmarks.is_empty());
        session.redo().unwrap();
        assert_eq!(session.inner.edits().bookmark(entry), Some("start here"));
        // An empty name removes it, undoably.
        session.bookmark(entry, Some(String::new()));
        assert_eq!(session.inner.edits().bookmark(entry), None);
        assert!(session.can_undo());
        drop(session);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
