//! Questions about a function's C answered beside it, off the C's own
//! worker ([`Question`], [`Session::ask`](crate::Session::ask)): verify
//! (`binbun::queries::verify`), why (`binbun::queries::evidence`), origin
//! (`binbun::queries::origin`), run with values (`binbun::run`), its
//! stages for the IR viewer (`binbun::stages`), and its place in the
//! call graph (`binbun::calls`: its callers' and its own call sites
//! with their C lines, paths from it).
//!
//! Three lanes, each a thread of the session: verification (seconds to
//! minutes on the worst functions) on one, the interactive questions on
//! another, the call graph's (a function's callers decompiled, a path
//! search) on the third, so a check or a search in progress never holds
//! up a hover or a run; the C's documents keep the session's worker.
//! Every question can be
//! cancelled ([`Asked::cancel`]): a verification and a run stop inside
//! their runs, the others are dropped before they start and their
//! answers once they end. Answers are kept per function, view and
//! question ([`Session::answer`](crate::Session::answer)): asked again,
//! a kept answer is told at once; but call sites, whose C lines print the
//! user's names, are made again each time (from the kept documents).
//! Whoever asked may also wait for the answer ([`Asked::wait`]).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use binbun::Database;
use binbun::calls::{Call, Node as Callee, PathQuery, Paths, data};
use binbun::cfg::FunctionId;
use binbun::decompile::{Decompiled, Options as DecompileOptions, View};
use binbun::profile::{self, Profile};
use binbun::queries::compare::{self, Comparison};
use binbun::queries::evidence::{Explanation, explain};
use binbun::queries::origin::{Origins, Query, Start, origins};
use binbun::queries::verify::{self, Verification};
use binbun::run::{self, ExampleState, Run};
use binbun::stages::{self, Stages};
use binbun_ast::ir::{Node, VarId};

use crate::Event;
use crate::calls::{CallSite, call_sites};
use crate::worker::{Shared, slot};

/// A question about a function in a view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Question {
    /// Whether its C does what its machine code does
    /// ([`verify::verify_cancellable`], the interactive check's options
    /// in the view: [`verify::Options::interactive`]), on a processor's
    /// profile if one ([`crate::Session::profile`]).
    Verify(Option<Arc<Profile>>),
    /// Why each variable has its type and name
    /// ([`binbun::queries::evidence::explain`]).
    Explain,
    /// Where a value comes from and where it goes
    /// ([`binbun::queries::origin::origins`], the default query in the
    /// view).
    Origins(Start),
    /// Its run from an example state ([`binbun::run::run_decompiled`], the
    /// machine code too), on a processor's profile if one.
    Run(Arc<ExampleState>, Option<Arc<Profile>>),
    /// Whether it behaves differently on the shipped processors' profiles
    /// ([`compare::compare_cancellable`], default options).
    Compare,
    /// It through every stage of decompilation
    /// ([`binbun::stages::stages_cancellable`], default options in the
    /// view).
    Stages,
    /// Every call reaching it, each with its caller's C line and its
    /// arguments' known values ([`CallSite`]).
    Callers,
    /// Every call it makes, likewise.
    Callees,
    /// The paths from it ([`PathRequest`]).
    Paths(Arc<PathRequest>),
}

/// A path search from a function ([`Question::Paths`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathRequest {
    /// Where the paths go ([`binbun::calls::CallGraph::paths`]).
    pub query: PathQuery,
    /// Only along calls the value of this parameter goes on through
    /// ([`binbun::calls::data::paths`]).
    pub data: Option<u8>,
}

impl Question {
    /// What answers to it are kept by: the question, a state by its TOML.
    fn key(&self) -> Topic {
        match self {
            Self::Verify(processor) => Topic::Verify(profile::label(processor.as_deref())),
            Self::Explain => Topic::Explain,
            Self::Origins(Start::Var(var)) => Topic::Var(*var),
            Self::Origins(Start::Node(node)) => Topic::Node(*node),
            Self::Run(state, processor) => Topic::Run(
                state.to_toml().unwrap_or_default(),
                profile::label(processor.as_deref()),
            ),
            Self::Compare => Topic::Compare,
            Self::Stages => Topic::Stages,
            Self::Callers => Topic::Callers,
            Self::Callees => Topic::Callees,
            Self::Paths(request) => Topic::Paths(PathRequest::clone(request)),
        }
    }

    /// The lane it goes on: 0 verification and comparison, 1 the
    /// interactive questions, 2 the call graph's.
    pub(crate) const fn lane(&self) -> usize {
        match self {
            Self::Verify(_) | Self::Compare => 0,
            Self::Explain | Self::Origins(_) | Self::Run(..) | Self::Stages => 1,
            Self::Callers | Self::Callees | Self::Paths(_) => 2,
        }
    }

    /// Whether its answer is kept (call sites' C lines print names, which
    /// an edit changes).
    pub(crate) const fn kept(&self) -> bool {
        !matches!(self, Self::Callers | Self::Callees)
    }
}

/// The answer to a [`Question`].
#[derive(Clone, Debug)]
pub enum Answer {
    /// The verification.
    Verified(Arc<Verification>),
    /// The explanation, or why there is none.
    Explained(Result<Arc<Explanation>, String>),
    /// The origins, or why there are none.
    Origins(Result<Arc<Origins>, String>),
    /// The run, or why there is none (it does not decompile, the state
    /// does not fit).
    Ran(Result<Arc<Run>, String>),
    /// The comparison of the processors.
    Compared(Arc<Comparison>),
    /// Its stages, or why there are none.
    Staged(Result<Arc<Stages>, String>),
    /// The call sites asked for, by caller and site.
    Calls(Arc<Vec<CallSite>>),
    /// The paths found.
    Paths(Arc<Paths>),
}

/// A question asked: its number, which the [`Event::Answer`] answering it
/// carries, what cancels it, and its answer once it comes
/// ([`Self::wait`]).
#[derive(Clone, Debug)]
pub struct Asked {
    /// The request's number.
    pub request: u64,
    cancel: Arc<AtomicBool>,
    reply: Arc<Reply>,
}

impl Asked {
    /// Stops the question: no answer is told (a verification or run in
    /// progress stops at its next step).
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Whether it was cancelled.
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// The answer, waiting for it up to `timeout` (`None`: as long as it
    /// takes); else why there is none.
    ///
    /// # Errors
    ///
    /// It was cancelled, the time ran out (asked again, a kept answer is
    /// told at once), or it is never to be answered (asked before the
    /// functions were recovered, or the session closed).
    pub fn wait(&self, timeout: Option<Duration>) -> Result<Answer, Unanswered> {
        let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        let mut replied = self.reply.lock();
        loop {
            match &*replied {
                Replied::Answered(answer) => return Ok(answer.clone()),
                Replied::Dropped | Replied::Pending if self.cancelled() => {
                    return Err(Unanswered::Cancelled);
                }
                Replied::Dropped => return Err(Unanswered::Dropped),
                Replied::Pending => {}
            }
            replied = match deadline {
                None => self
                    .reply
                    .ready
                    .wait(replied)
                    .unwrap_or_else(PoisonError::into_inner),
                Some(deadline) => {
                    let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                        return Err(Unanswered::TimedOut);
                    };
                    self.reply
                        .ready
                        .wait_timeout(replied, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
        }
    }
}

/// Why waiting for an answer gave none ([`Asked::wait`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unanswered {
    /// The time ran out; the question is still being answered.
    TimedOut,
    /// The question was cancelled.
    Cancelled,
    /// It is never to be answered: asked before the functions were
    /// recovered, or the session closed.
    Dropped,
}

/// Where a question's answer goes for whoever waits for it.
#[derive(Debug, Default)]
struct Reply {
    replied: Mutex<Replied>,
    ready: Condvar,
}

/// A question's answer, or not.
#[derive(Debug, Default)]
enum Replied {
    /// Not yet.
    #[default]
    Pending,
    /// This.
    Answered(Answer),
    /// Never.
    Dropped,
}

impl Reply {
    fn lock(&self) -> MutexGuard<'_, Replied> {
        self.replied.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Settles it as `replied`, unless it is settled.
    fn settle(&self, replied: Replied) {
        let mut now = self.lock();
        if matches!(*now, Replied::Pending) {
            *now = replied;
            self.ready.notify_all();
        }
    }
}

/// What answers are kept by, besides the function and view.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Topic {
    Verify(String),
    Explain,
    Var(VarId),
    Node(Node),
    Run(String, String),
    Compare,
    Stages,
    Callers,
    Callees,
    Paths(PathRequest),
}

/// A question for a lane.
pub(crate) struct Job {
    pub(crate) request: u64,
    pub(crate) function: FunctionId,
    pub(crate) view: View,
    pub(crate) question: Question,
    pub(crate) cancel: Arc<AtomicBool>,
    reply: Arc<Reply>,
}

impl Job {
    /// Its answer, for whoever waits for it.
    pub(crate) fn answer(&self, answer: Answer) {
        self.reply.settle(Replied::Answered(answer));
    }
}

impl Drop for Job {
    /// Never answered now: whoever waits stops waiting.
    fn drop(&mut self) {
        self.reply.settle(Replied::Dropped);
    }
}

/// The answers kept, by function, view and question, and the jobs the
/// lanes are answering (so that cancelling the session stops them).
#[derive(Default)]
pub(crate) struct Answers {
    kept: Mutex<BTreeMap<(FunctionId, u8, Topic), Answer>>,
    running: Mutex<Vec<Arc<AtomicBool>>>,
}

impl Answers {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<(FunctionId, u8, Topic), Answer>> {
        self.kept.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn running(&self) -> MutexGuard<'_, Vec<Arc<AtomicBool>>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Cancels every job being answered.
    pub(crate) fn cancel_running(&self) {
        for cancel in self.running().iter() {
            cancel.store(true, Ordering::Relaxed);
        }
    }

    /// The answer kept to `question` of `function` in `view`.
    pub(crate) fn get(
        &self,
        function: FunctionId,
        view: View,
        question: &Question,
    ) -> Option<Answer> {
        self.lock()
            .get(&(function, slot(view), question.key()))
            .cloned()
    }

    fn insert(&self, function: FunctionId, view: View, question: &Question, answer: Answer) {
        self.lock()
            .insert((function, slot(view), question.key()), answer);
    }

    /// Forgets the answer kept to `question` of `function` in `view`: it
    /// is asked anew (evidence checked against the analysis now).
    pub(crate) fn forget(&self, function: FunctionId, view: View, question: &Question) {
        self.lock().remove(&(function, slot(view), question.key()));
    }
}

/// A job for `question`, numbered `request`, cancelled by its [`Asked`].
pub(crate) fn job(
    request: u64,
    function: FunctionId,
    view: View,
    question: Question,
) -> (Job, Asked) {
    let cancel = Arc::new(AtomicBool::new(false));
    let reply = Arc::new(Reply::default());
    let asked = Asked {
        request,
        cancel: Arc::clone(&cancel),
        reply: Arc::clone(&reply),
    };
    (
        Job {
            request,
            function,
            view,
            question,
            cancel,
            reply,
        },
        asked,
    )
}

/// A lane: answers `jobs` in order until the session is gone or
/// cancelled, each once the functions are recovered.
pub(crate) fn lane(shared: &Shared, answers: &Answers, jobs: &Receiver<Job>) {
    while let Ok(job) = jobs.recv() {
        if shared.cancelled() {
            return;
        }
        if job.cancel.load(Ordering::Relaxed) {
            continue;
        }
        let Some(database) = shared.database() else {
            // Asked before the functions are recovered: no function to
            // answer about yet.
            continue;
        };
        answers.running().push(Arc::clone(&job.cancel));
        let answer = answers
            .get(job.function, job.view, &job.question)
            .or_else(|| answer(shared, database, &job));
        answers
            .running()
            .retain(|cancel| !Arc::ptr_eq(cancel, &job.cancel));
        if let Some(answer) = answer {
            if job.question.kept() {
                answers.insert(job.function, job.view, &job.question, answer.clone());
            }
            if !job.cancel.load(Ordering::Relaxed) {
                job.answer(answer.clone());
                shared.emit(&Event::Answer {
                    request: job.request,
                    function: job.function,
                    view: job.view,
                    answer,
                });
            }
        }
    }
}

/// The answer to `job`; `None` if it was cancelled before it ended.
fn answer(shared: &Shared, database: &Database<'_>, job: &Job) -> Option<Answer> {
    let cancel = &job.cancel;
    let answer = match &job.question {
        Question::Verify(processor) => {
            let options = verify::Options {
                profile: processor.clone(),
                ..verify::Options::interactive(job.view)
            };
            Answer::Verified(Arc::new(verify::verify_cancellable(
                database,
                job.function,
                &options,
                cancel,
            )?))
        }
        Question::Compare => Answer::Compared(Arc::new(compare::compare_cancellable(
            database,
            job.function,
            &compare::Options {
                fuel: Some(verify::INTERACTIVE_FUEL),
                ..compare::Options::default()
            },
            cancel,
        )?)),
        Question::Explain => {
            Answer::Explained(explain(database, job.function, job.view).map(Arc::new))
        }
        Question::Origins(start) => {
            let query = Query {
                view: job.view,
                ..Query::default()
            };
            Answer::Origins(origins(database, job.function, *start, &query).map(Arc::new))
        }
        Question::Run(state, processor) => {
            let options = run::Options {
                view: job.view,
                profile: processor.clone(),
                ..run::Options::default()
            };
            let ran = decompiled(shared, database, job.function, job.view).and_then(|decompiled| {
                run::run_decompiled(database, &decompiled, state, &options, cancel)
            });
            if matches!(&ran, Ok(ran) if ran.c.stop == run::Stop::Cancelled) {
                return None;
            }
            Answer::Ran(ran.map(Arc::new))
        }
        Question::Stages => {
            let options = stages::Options {
                view: job.view,
                ..stages::Options::default()
            };
            let made = stages::stages_cancellable(database, job.function, &options, cancel)?;
            Answer::Staged(made.map(Arc::new))
        }
        Question::Callers | Question::Callees => {
            let graph = database.calls();
            let calls: Vec<Call> = if job.question == Question::Callers {
                graph
                    .callers(Callee::Function(job.function))
                    .copied()
                    .collect()
            } else {
                graph.callees(job.function).to_vec()
            };
            Answer::Calls(Arc::new(call_sites(
                shared, database, &calls, job.view, cancel,
            )?))
        }
        Question::Paths(request) => {
            let found = match request.data {
                Some(parameter) => data::paths(database, &request.query, parameter, cancel),
                None => database.calls().paths(&request.query, cancel),
            };
            Answer::Paths(Arc::new(found?))
        }
    };
    (!cancel.load(Ordering::Relaxed)).then_some(answer)
}

/// Function `function` decompiled in `view`: the session's kept L2 (the
/// one its document's statements are of), else decompiled and kept.
pub(crate) fn decompiled(
    shared: &Shared,
    database: &Database<'_>,
    function: FunctionId,
    view: View,
) -> Result<Arc<Decompiled>, String> {
    let key = (function, slot(view));
    if let Some(kept) = shared.state().decompiled.get(&key).cloned() {
        return kept;
    }
    let options = DecompileOptions {
        style: None,
        view,
        ..DecompileOptions::default()
    };
    let decompiled = database.decompile(function, &options).result.map(Arc::new);
    shared
        .state()
        .decompiled
        .entry(key)
        .or_insert_with(|| decompiled.clone());
    decompiled
}
