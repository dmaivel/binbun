//! The session's worker thread and what it shares with the session
//! ([`Shared`]): it reads the file, parses it while hashing it on a thread
//! of its own (the key of its project), loads the project, reads its debug
//! information, recovers the functions, builds the cross-references and
//! what callers read, then serves requests for functions' C, warming the
//! decompiler's cache between them.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::cfg::FunctionId;
use binbun::corrections::{Bounds, Item};
use binbun::decompile::{Decompiled, Options as DecompileOptions, View};
use binbun::summary::callees_first;
use binbun_debuginfo::info::DebugModel;
use binbun_debuginfo::info::locate;
use binbun_debuginfo::symbols::Identity;
use binbun_loader::{Image, select};
use binbun_print::style::Style;
use binbun_sigpack::pack::Pack;

use crate::cell::{Analysed, Loaded};
use crate::document::{self, Document};
use crate::edits::{Edit, Edits, Typed, Unresolved, Variable};
use crate::identity;
use crate::journal::{self, Journal, Of};
use crate::listing::Overlay;
use crate::project::{self, Key as ProjectKey, Project};
use crate::signatures;
use crate::symbols::{self, Slot, SymbolState, Symbols};
use crate::write::Group;
use crate::{Change, DebugSource, Event, Stage, Waited, types};

/// Called with every event, on the thread that makes it; whether it still
/// listens (a channel's receiver not dropped).
pub(crate) type Callback = Arc<dyn Fn(&Event) -> bool + Send + Sync>;

/// A function in a view: what the caches are keyed by.
pub(crate) type Key = (FunctionId, u8);

/// `view` as part of a cache key.
pub(crate) fn slot(view: View) -> u8 {
    match view {
        View::Exact => 0,
        View::Reading => 1,
    }
}

/// What the session and its worker share.
pub(crate) struct Shared {
    /// The file.
    pub(crate) path: PathBuf,
    /// Where its project is.
    pub(crate) place: Place,
    /// Its project, once decided (before [`Stage::Image`]).
    pub(crate) project: OnceLock<Resolved>,
    /// The style the C is laid out in ([`Shared::style`]; changed by
    /// [`crate::Session::set_style`]).
    style: Mutex<Style>,
    /// Whether the worker warms every function's interfaces once idle.
    pub(crate) warm: bool,
    /// Where the debug information is.
    debug: DebugSource,
    /// Debug information from symbol servers.
    pub(crate) symbols: Symbols,
    /// Where this install's identity is kept.
    identity: Option<PathBuf>,
    /// The slice of a universal Mach-O file to open
    /// ([`crate::Options::arch`]).
    arch: Option<String>,
    /// How library signatures are matched ([`crate::Options::signatures`]).
    pub(crate) signatures: signatures::Options,
    /// What became of it.
    symbol_slot: Mutex<Slot>,
    /// The signature packs for the binary's target, read once (the exact
    /// pass's and the behaviour pass's).
    pub(crate) signature_packs: OnceLock<Vec<Pack>>,
    /// The file the debug information was read from, if any.
    pub(crate) debug_file: OnceLock<PathBuf>,
    /// The bytes and the image, once parsed.
    pub(crate) loaded: OnceLock<Arc<Loaded>>,
    /// The database, once recovered.
    pub(crate) analysed: OnceLock<Arc<Analysed>>,
    /// Set to stop the worker at its next step.
    pub(crate) cancelled: Arc<AtomicBool>,
    /// Counts the analyses before this one: the sessions it was opened
    /// again from ([`crate::Session::reanalysed`],
    /// [`crate::Session::with_debug`]).
    pub(crate) analysis: AtomicU64,
    /// The stage and the subscribers.
    hub: Mutex<Hub>,
    /// Told when the stage changes or the worker stops.
    changed: Condvar,
    /// The edits and what is printed.
    state: Mutex<State>,
    /// The edits that do not resolve, found so far: a lock taken last
    /// (none other is taken while it is held), so it can be read under
    /// the hub's or a lineage's.
    unresolved: Mutex<BTreeSet<Unresolved>>,
    /// The project held for writing ([`Project::hold`]): taken when it is
    /// decided (or passed on by the session this one follows), given up
    /// when the session is closed or dropped, not when its worker stops,
    /// which may be later.
    holding: Mutex<Holding>,
}

/// A session's hold on its project ([`Shared::holding`]).
#[derive(Default)]
struct Holding {
    /// The hold, shared with the sessions that follow this one.
    held: Option<Arc<project::Held>>,
    /// The session was closed: nothing is held from now.
    closed: bool,
}

/// Where a session's project is.
#[derive(Clone)]
pub(crate) enum Place {
    /// In this directory ([`crate::Options::project`]).
    Given(PathBuf),
    /// The binary's own in this projects directory (`None`:
    /// [`project::root`]), by its key once the file is hashed.
    Central(Option<PathBuf>),
    /// Decided already (a session opened again: [`crate::Session::with_debug`]).
    Known(Resolved),
    /// None: the edits are kept in memory only, nothing read or written
    /// ([`crate::Options::ephemeral`]).
    Ephemeral,
}

/// A session's project, decided.
#[derive(Clone)]
pub(crate) struct Resolved {
    /// The project; none for an ephemeral session.
    pub(crate) project: Option<Project>,
    /// The binary's key, if it was hashed (its project is its own).
    pub(crate) key: Option<ProjectKey>,
}

/// The stage reached, the symbol server state, and who hears of them.
struct Hub {
    stage: Stage,
    symbols: Option<SymbolState>,
    subscribers: Vec<Callback>,
    /// The last failure told ([`Event::Failed`]).
    failure: Option<String>,
    /// Whether the worker stopped.
    ended: bool,
}

/// Where a session's debug information comes from, and the signature
/// packs that name its library functions.
pub(crate) struct DebugInput {
    /// A file, the conventions, or none.
    pub(crate) source: DebugSource,
    /// Symbol servers.
    pub(crate) symbols: Symbols,
    /// Where this install's identity is kept ([`crate::Options::identity`]).
    pub(crate) identity: Option<PathBuf>,
    /// The slice of a universal Mach-O file to open, whose debug
    /// information is looked for ([`crate::Options::arch`]).
    pub(crate) arch: Option<String>,
    /// How library signatures are matched ([`crate::Options::signatures`]).
    pub(crate) signatures: signatures::Options,
}

/// The edits, and the functions decompiled and printed with them.
pub(crate) struct State {
    /// The user's edits: the journal's projection.
    pub(crate) edits: Edits,
    /// The changes they are the projection of, and the group open.
    pub(crate) journal: Journal,
    /// What the group open changed so far (its edits' effects merged).
    pub(crate) group: Option<Group>,
    /// Whether edits are saved to the project file as they are made (not
    /// if it could not be read: it is never overwritten then).
    pub(crate) autosave: bool,
    /// Counts the edits written, so a document printed while one is made
    /// is printed again.
    pub(crate) generation: u64,
    /// Counts the changes made or taken (carried over from the session it
    /// replaces): [`crate::Revision::edits`].
    pub(crate) changes: u64,
    /// Counts the project files written ([`crate::Session::saves`]).
    pub(crate) saves: u64,
    /// Counts the user's types taken by the database, so a function
    /// decompiled while they change is decompiled again.
    pub(crate) retyped: u64,
    /// Each function decompiled in each view asked for, or why it is not.
    pub(crate) decompiled: BTreeMap<Key, Result<Arc<Decompiled>, String>>,
    /// Each function printed with the edits, per view.
    pub(crate) documents: BTreeMap<Key, Arc<Document>>,
    /// The documents an edit changed since they were printed.
    pub(crate) stale: BTreeSet<Key>,
    /// The edits as the listing shows them, once asked for since they
    /// last changed ([`crate::Session::overlay`]).
    pub(crate) overlay: Option<Arc<Overlay>>,
}

/// What the session asks of the worker.
pub(crate) enum Request {
    /// Function `function`'s document in `view`, to `reply`.
    Document {
        /// The function.
        function: FunctionId,
        /// The view.
        view: View,
        /// Where the answer goes.
        reply: Reply,
    },
}

/// Where a request's answer goes.
pub(crate) enum Reply {
    /// An [`Event::Document`] with this request number.
    Event(u64),
    /// This channel (a blocking request).
    Channel(Sender<Result<Arc<Document>, String>>),
}

impl Shared {
    /// Nothing loaded yet of the file at `path`, its project where `place`
    /// says, `journal` (and `edits`, its projection) until the project's
    /// are loaded, its debug information where `debug` says.
    pub(crate) fn new(
        path: PathBuf,
        place: Place,
        style: Style,
        warm: bool,
        (edits, journal): (Edits, Journal),
        autosave: bool,
        debug: DebugInput,
    ) -> Self {
        let project = OnceLock::new();
        if let Place::Known(resolved) = &place {
            let _ = project.set(resolved.clone());
        }
        Self {
            path,
            place,
            project,
            style: Mutex::new(style),
            warm,
            debug: debug.source,
            symbols: debug.symbols,
            identity: debug.identity,
            arch: debug.arch,
            signatures: debug.signatures,
            symbol_slot: Mutex::new(Slot::default()),
            signature_packs: OnceLock::new(),
            debug_file: OnceLock::new(),
            loaded: OnceLock::new(),
            analysed: OnceLock::new(),
            cancelled: Arc::new(AtomicBool::new(false)),
            analysis: AtomicU64::new(0),
            hub: Mutex::new(Hub {
                stage: Stage::Opening,
                symbols: None,
                subscribers: Vec::new(),
                failure: None,
                ended: false,
            }),
            changed: Condvar::new(),
            state: Mutex::new(State {
                edits,
                journal,
                group: None,
                autosave,
                generation: 0,
                changes: 0,
                saves: 0,
                retyped: 0,
                decompiled: BTreeMap::new(),
                documents: BTreeMap::new(),
                stale: BTreeSet::new(),
                overlay: None,
            }),
            unresolved: Mutex::new(BTreeSet::new()),
            holding: Mutex::new(Holding::default()),
        }
    }

    /// The database, once recovered.
    pub(crate) fn database(&self) -> Option<&Database<'_>> {
        self.analysed
            .get()
            .map(|analysed| analysed.borrow_dependent())
    }

    /// The stage reached.
    pub(crate) fn stage(&self) -> Stage {
        self.hub().stage
    }

    /// The symbol server state last told, if any.
    pub(crate) fn symbol_state(&self) -> Option<SymbolState> {
        self.hub().symbols.clone()
    }

    /// Adds `subscriber`, telling it the stage reached, the symbol server
    /// state, the last failure and the edits found not to resolve so far
    /// first (under the lock they are told under: it misses none and
    /// hears none twice), so one that subscribes after opening failed
    /// early, or after the edits were checked, still hears what came of it.
    pub(crate) fn subscribe(&self, subscriber: Callback) {
        let mut hub = self.hub();
        let unresolved: Vec<Unresolved> = self.unresolved().iter().cloned().collect();
        if subscriber(&Event::Stage(hub.stage))
            && hub
                .symbols
                .as_ref()
                .is_none_or(|state| subscriber(&Event::Symbols(state.clone())))
            && hub
                .failure
                .as_ref()
                .is_none_or(|message| subscriber(&Event::Failed(message.clone())))
            && (unresolved.is_empty() || subscriber(&Event::Unresolved(unresolved.into())))
        {
            hub.subscribers.push(subscriber);
        }
    }

    /// Tells every subscriber `event`; a stage reached or a symbol server
    /// state first. Edits that do not resolve are told by
    /// [`Self::found_unresolved`].
    pub(crate) fn emit(&self, event: &Event) {
        let subscribers = {
            let mut hub = self.hub();
            match event {
                Event::Stage(stage) => {
                    hub.stage = *stage;
                    self.changed.notify_all();
                }
                Event::Symbols(state) => hub.symbols = Some(state.clone()),
                Event::Failed(message) => hub.failure = Some(message.clone()),
                Event::Progress { .. }
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
            hub.subscribers.clone()
        };
        self.tell(subscribers, event);
    }

    /// Tells `subscribers` `event`; those no longer listening are dropped.
    fn tell(&self, subscribers: Vec<Callback>, event: &Event) {
        let gone: Vec<Callback> = subscribers
            .into_iter()
            .filter(|subscriber| !subscriber(event))
            .collect();
        if !gone.is_empty() {
            self.hub()
                .subscribers
                .retain(|subscriber| !gone.iter().any(|gone| Arc::ptr_eq(gone, subscriber)));
        }
    }

    /// The edits and what is printed.
    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Where the identities of the agents this install signs for are kept
    /// (`agents` beside this install's identity); `None` for an ephemeral
    /// session or without binbun's configuration directory.
    pub(crate) fn agents_dir(&self) -> Option<PathBuf> {
        let ephemeral = match &self.place {
            Place::Ephemeral => true,
            Place::Known(resolved) => resolved.project.is_none(),
            Place::Given(_) | Place::Central(_) => false,
        };
        if ephemeral {
            return None;
        }
        self.identity
            .clone()
            .or_else(identity::root)
            .map(|dir| dir.join("agents"))
    }

    /// The style the C is laid out in now.
    pub(crate) fn style(&self) -> Style {
        *self.style.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Lays the C out in `style` from now on.
    pub(crate) fn set_style(&self, style: Style) {
        *self.style.lock().unwrap_or_else(PoisonError::into_inner) = style;
    }

    /// Whether the worker is to stop.
    pub(crate) fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn holding(&self) -> MutexGuard<'_, Holding> {
        self.holding.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Holds `project` for writing for the session's life
    /// ([`Project::hold`]).
    ///
    /// # Errors
    ///
    /// It is held elsewhere, or the session was closed meanwhile.
    fn hold(&self, project: &Project) -> Result<(), String> {
        let held = project.hold()?;
        let mut holding = self.holding();
        if holding.closed {
            return Err("the session was closed".to_owned());
        }
        holding.held = Some(Arc::new(held));
        Ok(())
    }

    /// The hold on the project, to pass on to a session that follows this
    /// one ([`Self::follow`]).
    pub(crate) fn held(&self) -> Option<Arc<project::Held>> {
        self.holding().held.clone()
    }

    /// Holds the project with `held`, the hold of the session this one
    /// follows.
    pub(crate) fn follow(&self, held: Option<Arc<project::Held>>) {
        let mut holding = self.holding();
        if !holding.closed {
            holding.held = held;
        }
    }

    /// Marks the hold on the project as let go of soon ([`project::Held::close`]):
    /// the session is closing, its worker finishing. Not if a session
    /// that follows this one holds it too: that one is still open.
    pub(crate) fn closing(&self) {
        let holding = self.holding();
        if let Some(held) = &holding.held
            && Arc::strong_count(held) == 1
        {
            held.close();
        }
    }

    /// Gives up the hold on the project: the session is closed or dropped.
    pub(crate) fn release(&self) {
        let mut holding = self.holding();
        holding.closed = true;
        holding.held = None;
    }

    fn hub(&self) -> MutexGuard<'_, Hub> {
        self.hub.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Marks the worker stopped, telling those waiting.
    pub(crate) fn end(&self) {
        self.hub().ended = true;
        self.changed.notify_all();
    }

    /// Waits for `stage` (as [`crate::Session::wait`] says) up to
    /// `timeout` (`None`: as long as it takes).
    pub(crate) fn wait(&self, stage: Stage, timeout: Option<Duration>) -> Waited {
        // Without warming, what callers read is as far as it goes.
        let stage = if self.warm {
            stage
        } else {
            stage.min(Stage::Callers)
        };
        let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        let mut hub = self.hub();
        loop {
            if hub.stage >= stage {
                return Waited::Reached(hub.stage);
            }
            if hub.ended || self.cancelled() {
                return Waited::Stopped {
                    stage: hub.stage,
                    failure: hub.failure.clone(),
                };
            }
            hub = match deadline {
                None => self
                    .changed
                    .wait(hub)
                    .unwrap_or_else(PoisonError::into_inner),
                Some(deadline) => {
                    let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                        return Waited::TimedOut(hub.stage);
                    };
                    self.changed
                        .wait_timeout(hub, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
        }
    }

    /// What became of the debug information on symbol servers.
    pub(crate) fn symbol_slot(&self) -> MutexGuard<'_, Slot> {
        self.symbol_slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The edits that do not resolve, found so far, locked (no other lock
    /// may be taken while it is held).
    pub(crate) fn unresolved(&self) -> MutexGuard<'_, BTreeSet<Unresolved>> {
        self.unresolved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Records `found` (edits that do not resolve) and reports those not
    /// reported yet: recorded under the hub's lock, as [`Self::subscribe`]
    /// tells them, so each subscriber hears of each once.
    pub(crate) fn found_unresolved(&self, found: Vec<Unresolved>) {
        let (new, subscribers) = {
            let hub = self.hub();
            let mut unresolved = self.unresolved();
            let new: Vec<Unresolved> = found
                .into_iter()
                .filter(|edit| unresolved.insert(edit.clone()))
                .collect();
            (new, hub.subscribers.clone())
        };
        if !new.is_empty() {
            self.tell(subscribers, &Event::Unresolved(new.into()));
        }
    }
}

/// The worker: opens the file, analyses it stage by stage, then serves
/// `requests` (warming between them) until the session is gone or
/// cancelled.
pub(crate) fn run(shared: &Arc<Shared>, requests: &Receiver<Request>) {
    let Some(database) = analyse(shared) else {
        return;
    };
    signatures::behaviour(shared);
    let order = if shared.warm {
        callees_first(database.program())
    } else {
        Vec::new()
    };
    let mut warmed = 0;
    loop {
        // Cancelled, it serves no request more, even one sent before: its
        // answer is an error (as `Session::cancel` says).
        loop {
            if shared.cancelled() {
                return;
            }
            match requests.try_recv() {
                Ok(request) => serve(shared, database, request),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        if let Some(&function) = order.get(warmed) {
            if warmed % 256 == 0 {
                shared.emit(&Event::Progress {
                    warmed,
                    total: order.len(),
                });
                if shared.cancelled() {
                    return;
                }
            }
            database.warm(function, &[]);
            warmed += 1;
            continue;
        }
        if shared.warm && shared.stage() < Stage::Warmed {
            shared.emit(&Event::Progress {
                warmed,
                total: order.len(),
            });
            shared.emit(&Event::Stage(Stage::Warmed));
        }
        match requests.recv() {
            Ok(request) if !shared.cancelled() => serve(shared, database, request),
            Ok(_) | Err(_) => return,
        }
    }
}

/// The stages up to what callers read, each announced; the database, unless
/// the file cannot be opened or the session is cancelled.
fn analyse(shared: &Arc<Shared>) -> Option<&Database<'_>> {
    let loaded = match shared.loaded.get() {
        // Opened again ([`crate::Session::reanalysed`]): the same bytes
        // and image, the project known.
        Some(loaded) => Arc::clone(loaded),
        None => load(shared)?,
    };
    shared.emit(&Event::Stage(Stage::Image));
    if shared.cancelled() {
        return None;
    }
    let debug = debug(shared, &loaded);
    if shared.cancelled() {
        return None;
    }
    let corrections = shared.state().edits.corrections().clone();
    let analysed = Analysed::try_new(loaded, |loaded| {
        Database::with_corrections(loaded.borrow_dependent(), Seeds::ALL, debug, corrections)
    })
    .map_err(|error| {
        shared.emit(&Event::Failed(format!(
            "{}: {error}",
            shared.path.display()
        )));
    })
    .ok()?;
    let database = shared
        .analysed
        .get_or_init(|| Arc::new(analysed))
        .borrow_dependent();
    let edits = shared.state().edits.clone();
    shared.found_unresolved(resolve(database, &edits));
    if !edits.types().is_empty() || !edits.definitions().is_empty() {
        let (user, unresolved) = types::user_types(database, &edits);
        database.set_user(user);
        shared.found_unresolved(unresolved);
    }
    let whole = whole(database);
    shared.emit(&Event::Stage(Stage::Analysed));
    shared.emit(&Event::Changed(Arc::new(Change {
        documents: Vec::new(),
        listing: whole.clone(),
    })));
    if shared.cancelled() {
        return None;
    }
    let _ = database.references();
    shared.emit(&Event::Stage(Stage::Referenced));
    shared.emit(&Event::Changed(Arc::new(Change {
        documents: Vec::new(),
        listing: whole,
    })));
    if shared.cancelled() {
        return None;
    }
    signatures::exact(shared, database);
    shared.emit(&Event::Stage(Stage::Signatures));
    if shared.cancelled() {
        return None;
    }
    // Both views' at once: the C shown first reads the reading view's,
    // and documents and global types the exact view's.
    let _ = database.callers_both(&[]);
    shared.emit(&Event::Stage(Stage::Callers));
    (!shared.cancelled()).then_some(database)
}

/// Reads and parses the file (hashing it meanwhile, for its project),
/// decides its project and loads its edits; the bytes and image, unless
/// the file cannot be opened, the project read, or the session is
/// cancelled. Of a universal Mach-O file, the slice
/// [`Shared::arch`] chooses is parsed and keys the project: its bytes are
/// what a thin copy of it (`lipo -thin`) holds.
fn load(shared: &Arc<Shared>) -> Option<Arc<Loaded>> {
    let failed = |message: String| {
        shared.emit(&Event::Failed(format!(
            "{}: {message}",
            shared.path.display()
        )));
    };
    let bytes = fs::read(&shared.path)
        .map_err(|error| failed(error.to_string()))
        .ok()?;
    if shared.cancelled() {
        return None;
    }
    // The key is hashed while the image is parsed, and waited for only
    // if parsing ends first.
    let hash = matches!(shared.place, Place::Central(_) | Place::Ephemeral);
    let mut key = None;
    let arch = shared.arch.as_deref();
    let loaded = Loaded::try_new(bytes, |bytes| {
        thread::scope(|scope| {
            let name = project::file_name(&shared.path);
            let image_bytes = select(bytes, arch).map_or(bytes.as_slice(), |(slice, _)| slice);
            let hashing = hash.then(|| {
                thread::Builder::new()
                    .name("binbun-hash".to_owned())
                    .spawn_scoped(scope, || ProjectKey::new(image_bytes, name))
            });
            let image = Image::parse_arch(bytes, arch);
            key = hashing.and_then(|hashing| hashing.ok()?.join().ok());
            image
        })
    })
    .map_err(|error| failed(error.to_string()))
    .ok()?;
    let of = binding(
        loaded.borrow_owner(),
        loaded.borrow_dependent(),
        key.as_ref(),
    );
    // The key knows the file it was read from: what an export of the
    // project checks its log against (a slice's hash is the same in every
    // container holding it).
    let key = key.map(|key| key.from_file(of.clone()));
    if let Err(message) = decide_project(shared, key, of) {
        shared.emit(&Event::Failed(format!("project: {message}")));
        return None;
    }
    Some(Arc::clone(shared.loaded.get_or_init(|| Arc::new(loaded))))
}

/// What the file `data` (its image `image`, its project's key `key` if
/// hashed) is as a journal's chains name it: the whole file's SHA-256,
/// and the slice's architecture of a universal file.
fn binding(data: &[u8], image: &Image<'_>, key: Option<&ProjectKey>) -> Of {
    let slice = image.slice.as_ref().map(|slice| slice.arch.clone());
    let sha256 = match (key, &slice) {
        (Some(key), None) => *key.sha256(),
        _ => *ProjectKey::new(data, "").sha256(),
    };
    Of::Binary { sha256, slice }
}

/// What `of` names, for people.
fn described(of: &Of) -> String {
    match of {
        Of::Binary { sha256, slice } => format!(
            "SHA-256 {}{}",
            journal::store::hex(sha256),
            slice
                .as_ref()
                .map_or_else(String::new, |slice| format!(", slice {slice}"))
        ),
        Of::Set => "a set of binaries".to_owned(),
    }
}

/// Decides the session's project where [`Shared::place`] says (the
/// binary's own by its `key`), makes its directory, holds it for writing
/// ([`Project::hold`]) and loads its edits in place of those made so far
/// (a new log's chains of `of`); why not. A share's log bound to other
/// bytes than `of`, the file as opened, is not opened (sync §14.3).
fn decide_project(shared: &Shared, key: Option<ProjectKey>, of: Of) -> Result<(), String> {
    let project = match &shared.place {
        Place::Known(_) => return Ok(()),
        Place::Ephemeral => {
            shared.state().journal.bind(of);
            let _ = shared.project.set(Resolved { project: None, key });
            return Ok(());
        }
        Place::Given(dir) => Project::new(dir.clone()),
        Place::Central(root) => {
            let root = root
                .clone()
                .or_else(project::root)
                .ok_or_else(|| binbun_paths::Dir::Data.missing())?;
            let key = key.as_ref().ok_or("the file could not be hashed")?;
            project::locate(&root, key, &project::Choice::Any)?.project
        }
    };
    fs::create_dir_all(project.dir())
        .map_err(|error| format!("{}: {error}", project.dir().display()))?;
    shared.hold(&project)?;
    let log = journal::store::Store::new(project.dir().join("log"));
    if log.genesis()?.is_some()
        && let Some(bound) = log.bound()?
        && bound != of
    {
        return Err(format!(
            "{}: the share's log is of {}, not of the file opened ({}): it is not opened",
            project.dir().display(),
            described(&bound),
            described(&of)
        ));
    }
    let dir = shared
        .identity
        .clone()
        .or_else(identity::root)
        .ok_or_else(|| binbun_paths::Dir::Config.missing())?;
    let identity = identity::Identity::load_or_create(&dir)?;
    let (edits, mut journal) = journal::open(&project, &identity, of)?;
    let mut state = shared.state();
    // The agents signed for so far sign on in the project's journal.
    journal.carry_agents(&state.journal)?;
    state.edits = edits;
    state.journal = journal;
    state.overlay = None;
    let _ = shared.project.set(Resolved {
        project: Some(project),
        key,
    });
    Ok(())
}

/// The debug information of the file `loaded`, where
/// [`Shared::debug`] says, its file recorded; a file given that cannot be
/// read is reported ([`Event::Failed`]) and none taken. Searched for and
/// not where the conventions put it, it is taken from a local symbol
/// store, else offered from a symbol server ([`symbols::offer`]); a file
/// where the conventions put it that is another build's is reported
/// ([`Event::Failed`]) and passed over, never taken.
fn debug(shared: &Arc<Shared>, loaded: &Loaded) -> Option<DebugModel> {
    // A universal file's debug information is its opened slice's.
    let data = image_bytes(loaded.borrow_owner(), loaded.borrow_dependent());
    let (file, model) = match &shared.debug {
        DebugSource::Without => return None,
        DebugSource::Path(file) => match locate::open(file, &shared.path, data) {
            Ok(model) => (file.clone(), model),
            Err(message) => {
                shared.emit(&Event::Failed(message));
                return None;
            }
        },
        DebugSource::Search => {
            let searched = locate::Search::from_environment().search(&shared.path, data);
            for (file, reason) in &searched.passed {
                shared.emit(&Event::Failed(format!(
                    "{}: not used: {reason}",
                    file.display()
                )));
            }
            if let Some(found) = searched.found {
                (found.path, found.model)
            } else {
                let identity = Identity::of(data)?;
                let Some(file) = symbols::local(shared, &identity) else {
                    symbols::offer(shared, identity);
                    return None;
                };
                match locate::open(&file, &shared.path, data) {
                    Ok(model) => (file, model),
                    Err(message) => {
                        shared.emit(&Event::Failed(message));
                        return None;
                    }
                }
            }
        }
    };
    let _ = shared.debug_file.set(file);
    Some(model)
}

/// The bytes of `image` in its file `data`: its slice's, of a universal
/// file.
fn image_bytes<'data>(data: &'data [u8], image: &Image<'_>) -> &'data [u8] {
    image
        .slice
        .as_ref()
        .and_then(|slice| slice.bytes(data))
        .unwrap_or(data)
}

/// The image's addresses: its segments', merged.
pub(crate) fn whole(database: &Database<'_>) -> Vec<Range<u64>> {
    merge(
        database
            .image()
            .segments
            .iter()
            .map(|segment| segment.start..segment.end())
            .collect(),
    )
}

/// `ranges` sorted, those that overlap or touch made one.
pub(crate) fn merge(mut ranges: Vec<Range<u64>>) -> Vec<Range<u64>> {
    ranges.retain(|range| !range.is_empty());
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged
}

/// The edits that do not resolve in `database`: no function starts at a
/// function's entry (or a variable's function's); no segment holds a
/// global or a comment's or bookmark's address. (A variable of a function
/// is resolved when its function is printed.)
pub(crate) fn resolve(database: &Database<'_>, edits: &Edits) -> Vec<Unresolved> {
    let mapped = |address: u64| {
        database
            .image()
            .segments
            .iter()
            .any(|segment| (segment.start..segment.end()).contains(&address))
    };
    edits
        .all()
        .filter_map(|edit| {
            let why = match &edit {
                Edit::Function { entry, .. } => (database.function_at(*entry).is_none())
                    .then(|| format!("no function starts at {entry:#x}")),
                Edit::Global { address, .. }
                | Edit::Comment { address, .. }
                | Edit::Bookmark { address, .. }
                | Edit::Number { address, .. } => {
                    (!mapped(*address)).then(|| format!("no segment holds {address:#x}"))
                }
                Edit::Variable {
                    variable: Variable { function, .. },
                    ..
                }
                | Edit::Slot { function, .. } => (database.function_at(*function).is_none())
                    .then(|| format!("no function starts at {function:#x}")),
                Edit::Type { typed, .. } => match typed {
                    Typed::Prototype(entry) => (database.function_at(*entry).is_none())
                        .then(|| format!("no function starts at {entry:#x}")),
                    Typed::Global(address) => {
                        (!mapped(*address)).then(|| format!("no segment holds {address:#x}"))
                    }
                    Typed::Variable(Variable { function, .. }) | Typed::Struct { function, .. } => {
                        (database.function_at(*function).is_none())
                            .then(|| format!("no function starts at {function:#x}"))
                    }
                },
                Edit::Definition { .. } => None,
                // A correction recovery could not honour.
                Edit::Item { address, item } => match item {
                    _ if !mapped(*address) => Some(format!("no segment holds {address:#x}")),
                    Item::Code => (database.program().block_at(*address).is_none())
                        .then(|| format!("no code decodes at {address:#x}")),
                    Item::Undefined { .. } | Item::Data(_) => None,
                },
                Edit::Bounds { entry, bounds } => match bounds {
                    Bounds::Function { .. } => (database.function_at(*entry).is_none())
                        .then(|| format!("no function can start at {entry:#x}")),
                    Bounds::Deleted => database
                        .function_at(*entry)
                        .map(|_| format!("a function still starts at {entry:#x}")),
                },
            }?;
            Some(Unresolved { edit, why })
        })
        .collect()
}

/// Answers `request`.
fn serve(shared: &Shared, database: &Database<'_>, request: Request) {
    let Request::Document {
        function,
        view,
        reply,
    } = request;
    let result = document(shared, database, function, view);
    match reply {
        Reply::Event(request) => shared.emit(&Event::Document {
            request,
            function,
            result,
        }),
        Reply::Channel(sender) => {
            let _ = sender.send(result);
        }
    }
}

/// Function `function`'s document in `view`: as printed, unless an edit
/// changed it since; else its kept L2 printed again; else decompiled first.
pub(crate) fn document(
    shared: &Shared,
    database: &Database<'_>,
    function: FunctionId,
    view: View,
) -> Result<Arc<Document>, String> {
    let key = (function, slot(view));
    loop {
        let (decompiled, edits, generation, retyped, style) = {
            let state = shared.state();
            if let Some(document) = state.documents.get(&key)
                && !state.stale.contains(&key)
            {
                return Ok(Arc::clone(document));
            }
            (
                state.decompiled.get(&key).cloned(),
                state.edits.clone(),
                state.generation,
                state.retyped,
                shared.style(),
            )
        };
        let decompiled = if let Some(decompiled) = decompiled {
            decompiled
        } else {
            let options = DecompileOptions {
                style: None,
                view,
                ..DecompileOptions::default()
            };
            let decompiled = database.decompile(function, &options).result.map(Arc::new);
            let mut state = shared.state();
            if state.retyped != retyped {
                // The user's types changed while decompiling: again.
                continue;
            }
            state.decompiled.insert(key, decompiled.clone());
            drop(state);
            decompiled
        }?;
        let printed = Arc::new(document::print(
            database,
            function,
            view,
            &decompiled,
            &edits,
            &style,
        )?);
        let mut state = shared.state();
        if state.generation != generation {
            // An edit (or a style change) was made while printing: print
            // with it.
            continue;
        }
        state.documents.insert(key, Arc::clone(&printed));
        state.stale.remove(&key);
        drop(state);
        shared.found_unresolved(printed.unresolved.clone());
        return Ok(printed);
    }
}
