//! A binary's sessions in succession ([`Lineage`]): corrections of
//! recovery and debug information fetched are taken by analysing the
//! binary anew ([`crate::Session::reanalysed`],
//! [`crate::Session::with_debug`]) beside the session in use, which the
//! new one replaces once its functions are recovered ([`Lineage::swap`]):
//! with the edits made meanwhile (the journal: its history, undo and redo
//! and the group open), its functions by their old ids
//! ([`Swapped::functions`]), analysed anew again if corrections changed
//! meanwhile. Subscribers hear one stream: the session in use's events,
//! then [`Event::Reanalysed`] and what the new one told meanwhile.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use binbun::Database;
use binbun::cfg::FunctionId;

use crate::worker::Callback;
use crate::{Error, Event, Options, Session, Stage, SymbolState, Unresolved, Waited, Wake};

/// What a swap did ([`Lineage::swap`]).
#[derive(Clone, Debug)]
pub struct Swapped {
    /// The functions of the analysis before that the new one has too (by
    /// entry): their ids now, by their ids before.
    pub functions: Arc<HashMap<FunctionId, FunctionId>>,
}

/// A binary's session in use and the one analysing anew to take its
/// place, with one stream of events.
pub struct Lineage {
    current: RwLock<Arc<Session>>,
    next: Mutex<Option<Arc<Session>>>,
    relay: Arc<Mutex<Relay>>,
}

impl std::fmt::Debug for Lineage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lineage")
            .field("current", &self.session())
            .field("reanalysing", &self.reanalysing())
            .finish()
    }
}

/// Who hears the lineage's events, and from which session.
struct Relay {
    subscribers: Vec<Callback>,
    /// The session in use's number: its events are told.
    current: u64,
    /// The new one's: its events are held until it takes over.
    next: Option<u64>,
    /// The last number given.
    given: u64,
    held: Vec<Event>,
    /// The stage, symbol server state and failure the session in use told
    /// last.
    stage: Stage,
    symbols: Option<SymbolState>,
    failure: Option<String>,
    /// The edits the session in use told do not resolve.
    unresolved: BTreeSet<Unresolved>,
}

impl Relay {
    /// `event` of session `from`: told, held or dropped.
    fn forward(&mut self, from: u64, event: &Event) {
        if from == self.current {
            self.tell(event);
        } else if Some(from) == self.next {
            self.held.push(event.clone());
        }
    }

    /// Tells every subscriber `event`.
    fn tell(&mut self, event: &Event) {
        match event {
            Event::Stage(stage) => self.stage = *stage,
            Event::Symbols(state) => self.symbols = Some(state.clone()),
            Event::Failed(message) => self.failure = Some(message.clone()),
            Event::Unresolved(found) => self.unresolved.extend(found.iter().cloned()),
            Event::Progress { .. }
            | Event::Changed(_)
            | Event::Document { .. }
            | Event::Answer { .. }
            | Event::History(_)
            | Event::Conflicts(_)
            | Event::Thread(_)
            | Event::Mentioned(_)
            | Event::Bookmarks
            | Event::Reanalysed { .. } => {}
        }
        self.subscribers.retain(|subscriber| subscriber(event));
    }
}

impl Lineage {
    /// Opens the binary at `path` ([`Session::open`]).
    ///
    /// # Errors
    ///
    /// As [`Session::open`].
    pub fn open(path: impl Into<PathBuf>, options: Options) -> Result<Self, Error> {
        Session::open(path, options).map(Self::new)
    }

    /// `session`, in use.
    pub fn new(session: Session) -> Self {
        let lineage = Self {
            current: RwLock::new(Arc::new(session)),
            next: Mutex::new(None),
            relay: Arc::new(Mutex::new(Relay {
                subscribers: Vec::new(),
                current: 0,
                next: None,
                given: 0,
                held: Vec::new(),
                stage: Stage::Opening,
                symbols: None,
                failure: None,
                unresolved: BTreeSet::new(),
            })),
        };
        lineage.listen(&lineage.session(), 0);
        lineage
    }

    /// Relays `session`'s events as session `number`'s.
    fn listen(&self, session: &Session, number: u64) {
        let relay = Arc::clone(&self.relay);
        session.on_event(move |event| {
            relay
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .forward(number, event);
        });
    }

    fn relay(&self) -> MutexGuard<'_, Relay> {
        self.relay.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The session in use: where edits are made and read.
    pub fn session(&self) -> Arc<Session> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Every event from now on, on a channel, `wake` called after each is
    /// sent: the session in use's (first the stage it reached, its symbol
    /// server state, its last failure and the edits it found not to
    /// resolve, if any), [`Event::Reanalysed`] when a new one takes its
    /// place, then the new one's. Dropping the receiver unsubscribes.
    pub fn subscribe(&self, wake: Option<Wake>) -> Receiver<Event> {
        let (sender, receiver) = mpsc::channel();
        let subscriber: Callback = Arc::new(move |event: &Event| {
            let listening = sender.send(event.clone()).is_ok();
            if listening && let Some(wake) = &wake {
                wake();
            }
            listening
        });
        let mut relay = self.relay();
        let symbols = relay.symbols.clone().map(Event::Symbols);
        let failure = relay.failure.clone().map(Event::Failed);
        // Those told that still do not resolve (an edit of the same key
        // since drops one): the session's own are read under the relay's
        // lock, so one it tells later is told to this subscriber then.
        let now = self.session().unresolved();
        relay.unresolved.retain(|edit| now.contains(edit));
        let unresolved = (!relay.unresolved.is_empty())
            .then(|| Event::Unresolved(relay.unresolved.iter().cloned().collect()));
        let first = [
            Some(Event::Stage(relay.stage)),
            symbols,
            failure,
            unresolved,
        ];
        if first.iter().flatten().all(|event| subscriber(event)) {
            relay.subscribers.push(subscriber);
        }
        receiver
    }

    /// Waits up to `timeout` (`None`: as long as it takes) for the new
    /// analysis under way to recover the functions, without swapping it
    /// in: its events are held until [`Self::swap`], so a front end that
    /// swaps when it hears from the lineage learns here when to.
    /// `Some(true)` once it has, `Some(false)` if the time ran out first,
    /// `None` if none is under way or it stopped.
    pub fn ready(&self, timeout: Option<Duration>) -> Option<bool> {
        let next = self.next().clone()?;
        match next.wait(Stage::Analysed, timeout) {
            Waited::Reached(_) => Some(true),
            Waited::TimedOut(_) => Some(false),
            Waited::Stopped { .. } => None,
        }
    }

    /// Whether the binary is being analysed anew.
    pub fn reanalysing(&self) -> bool {
        self.next().is_some()
    }

    fn next(&self) -> MutexGuard<'_, Option<Arc<Session>>> {
        self.next.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Analyses the binary anew with the corrections the edits hold now
    /// ([`Session::reanalysed`]), if the session in use was not recovered
    /// with them and none is under way (one under way is followed by
    /// another at its swap if they changed meanwhile); whether it started.
    ///
    /// # Errors
    ///
    /// As [`Session::reanalysed`].
    pub fn reanalyse(&self) -> Result<bool, Error> {
        let current = self.session();
        if current.recovered_as_corrected() != Some(false) {
            return Ok(false);
        }
        let mut next = self.next();
        if next.is_some() {
            return Ok(false);
        }
        *next = Some(self.successor(current.reanalysed()?));
        Ok(true)
    }

    /// Opens the binary anew with the debug information at `file`
    /// ([`Session::with_debug`]), in place of a new analysis under way.
    ///
    /// # Errors
    ///
    /// As [`Session::with_debug`].
    pub fn with_debug(&self, file: impl Into<PathBuf>) -> Result<(), Error> {
        let session = self.session().with_debug(file)?;
        *self.next() = Some(self.successor(session));
        Ok(())
    }

    /// `session` as the next to take the place of the one in use, its
    /// events held until it does.
    fn successor(&self, session: Session) -> Arc<Session> {
        let number = {
            let mut relay = self.relay();
            relay.given += 1;
            relay.next = Some(relay.given);
            relay.held.clear();
            relay.given
        };
        self.listen(&session, number);
        Arc::new(session)
    }

    /// Waits up to `timeout` (`None`: as long as it takes) for the new
    /// analysis under way to recover the functions, then swaps it in; what
    /// the swap did, if one was made (none under way, or it stopped or ran
    /// out of time first).
    pub fn wait(&self, timeout: Option<Duration>) -> Option<Swapped> {
        match self.wait_next(timeout)? {
            Waited::Reached(_) => self.swap(),
            Waited::TimedOut(_) | Waited::Stopped { .. } => None,
        }
    }

    /// Waits up to `timeout` (`None`: as long as it takes) for the new
    /// analysis under way to recover the functions, without swapping it
    /// in (whoever makes the edits swaps: [`Self::swap`]): what the wait
    /// came to; `None` if none is under way.
    pub fn wait_next(&self, timeout: Option<Duration>) -> Option<Waited> {
        let next = self.next().clone()?;
        Some(next.wait(Stage::Analysed, timeout))
    }

    /// Puts the new analysis in place of the one in use, once its
    /// functions are recovered: it takes the edits as they are now
    /// ([`Session::take_edits`]), [`Event::Reanalysed`] is told and then
    /// what it told meanwhile, and a correction made meanwhile has the
    /// binary analysed anew again. What it did; `None` if no new analysis
    /// is ready. Call it from where edits are made (an edit made in the
    /// session replaced while it swaps would be lost).
    pub fn swap(&self) -> Option<Swapped> {
        let next = {
            let mut next = self.next();
            if next
                .as_ref()
                .is_none_or(|next| next.stage() < Stage::Analysed)
            {
                return None;
            }
            next.take()?
        };
        let before = self.session();
        // The style set while it was being analysed.
        next.set_style(before.style());
        next.take_edits(&before);
        let functions = Arc::new(renumbered(before.database(), next.database()));
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::clone(&next);
        {
            let mut relay = self.relay();
            relay.current = relay.next.take()?;
            // The new session's own failure, if any, comes with its held
            // events; the one before's is not its.
            relay.failure = None;
            relay.unresolved.clear();
            relay.tell(&Event::Reanalysed {
                revision: next.revision(),
                functions: Arc::clone(&functions),
            });
            for event in std::mem::take(&mut relay.held) {
                relay.tell(&event);
            }
        }
        // Corrections made while it was being analysed: again.
        if let Err(error) = self.reanalyse() {
            self.relay().tell(&Event::Failed(error.to_string()));
        }
        Some(Swapped { functions })
    }

    /// Closes the sessions: the one in use, and the new one under way;
    /// waits for their threads to stop where nothing else holds them.
    pub fn close(self) {
        let next = self.next().take();
        let current = self
            .current
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        for session in [Some(current), next].into_iter().flatten() {
            match Arc::try_unwrap(session) {
                Ok(session) => session.close(),
                Err(held) => held.cancel(),
            }
        }
    }
}

/// The functions of `old` that `new` has too (by entry): their ids there,
/// by their ids in `old`.
fn renumbered(
    old: Option<&Database<'_>>,
    new: Option<&Database<'_>>,
) -> HashMap<FunctionId, FunctionId> {
    let (Some(old), Some(new)) = (old, new) else {
        return HashMap::new();
    };
    old.functions()
        .filter_map(|(id, function)| Some((id, new.function_at(function.entry)?)))
        .collect()
}
