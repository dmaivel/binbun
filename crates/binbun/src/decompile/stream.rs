//! Every function of a program in L1, handed over callees first with the
//! interfaces of the program's functions ([`stream`]), and what is done
//! with each then on worker threads ([`stream_parallel`]).

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;

use binbun_decompile::data::Data;
use binbun_decompile::lower::{self as lowering, Context, Facts, Found, Interface};
use binbun_decompile::prototype::Prototypes;
use binbun_decompile::typing::Summary;
use binbun_loader::Image;
use binbun_semantics::core::pass::PassStats;
use binbun_ssa::constant::Constants;
use binbun_ssa::graph::Dominators;
use binbun_ssa::ir::Function;
use binbun_ssa::stack::Stack;

use super::callers::Callers;
use super::{Prepared, decompile_l1, with_context};
use crate::cfg::{FunctionId, Program};
use crate::summary::{Summaries, callees_first};

/// What lowering knows about the functions of a program ([`stream`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Interfaces {
    /// Each function's parameters and return value, by entry.
    pub interfaces: BTreeMap<u64, Interface>,
    /// Every function's entry.
    pub functions: BTreeSet<u64>,
    /// What callers read of each function ([`Callers`]): a function's own
    /// lowering drops a return value no caller reads.
    pub callers: Callers,
}

impl Interfaces {
    /// The interfaces of the functions of `program` `callers` found
    /// ([`Callers::interfaces`]), whose callers read what it says.
    pub(crate) fn of(program: &Program, callers: &Callers) -> Self {
        Self {
            interfaces: callers.interfaces.clone(),
            functions: program.functions.iter().map(|(_, f)| f.entry).collect(),
            callers: callers.clone(),
        }
    }
}

/// Every function of `program` (recovered from `image`, with `summaries`
/// and what its callers `read` of it) in L1 as decompilation starts from
/// it ([`decompile_l1`], but the passes `disabled`), or why it is not,
/// handed to `ready` once, callees first ([`callees_first`]), with the
/// interfaces of the program's functions: those `read` found for the whole
/// program ([`Callers::interfaces`]), the one each function's definition
/// and every call to it take. Each function is lifted once, as it is
/// handed over.
pub fn stream(
    image: &Image<'_>,
    program: &Program,
    summaries: &Summaries,
    read: &Callers,
    disabled: &[String],
    mut ready: impl FnMut(FunctionId, Result<Prepared, String>, &Interfaces),
) {
    let known = Interfaces::of(program, read);
    let order = callees_first(program);
    lifted(
        image,
        program,
        &order,
        summaries,
        disabled,
        1,
        |id, prepared| {
            ready(id, prepared, &known);
        },
    );
}

/// [`stream`], with `work` done on each function handed over on `threads`
/// worker threads while the stream goes on, and its results handed to
/// `ready` in the order [`stream`] hands the functions over; with one
/// thread (or none), `work` is done as each is handed over, on this
/// thread, as [`stream`] does. Every worker reads the one set of
/// interfaces, so each function's work sees exactly what [`stream`] would
/// give it. The stream's L1 is lifted ahead of it on `threads` more
/// threads (it reads only the finished `summaries`), handed over in its
/// order.
#[expect(
    clippy::too_many_arguments,
    reason = "what decompilation reads of the program, and how to share the work"
)]
pub fn stream_parallel<T: Send>(
    image: &Image<'_>,
    program: &Program,
    summaries: &Summaries,
    read: &Callers,
    disabled: &[String],
    threads: usize,
    work: impl Fn(FunctionId, Result<Prepared, String>, &Interfaces) -> T + Sync,
    mut ready: impl FnMut(T),
) {
    if threads <= 1 {
        stream(
            image,
            program,
            summaries,
            read,
            disabled,
            |id, prepared, known| {
                ready(work(id, prepared, known));
            },
        );
        return;
    }
    let known = Interfaces::of(program, read);
    let order = callees_first(program);
    // A few functions queued per worker, so the stream runs ahead of the
    // work but holds little.
    let (jobs, queue) = mpsc::sync_channel::<Job>(threads.saturating_mul(2));
    let queue = Arc::new(Mutex::new(queue));
    let (done, results) = mpsc::channel();
    thread::scope(|scope| {
        for _ in 0..threads {
            let (queue, done, known, work) = (Arc::clone(&queue), done.clone(), &known, &work);
            scope.spawn(move || {
                while let Some(job) = next(&queue) {
                    let prepared = job.prepared.map(Moved::prepared);
                    if done.send((job.at, work(job.id, prepared, known))).is_err() {
                        break;
                    }
                }
            });
        }
        // The workers hold the queue and the results' senders: if they all
        // stop, the stream's sends and the wait for results end.
        drop((queue, done));
        let mut in_order = InOrder::default();
        let mut at = 0;
        lifted(
            image,
            program,
            &order,
            summaries,
            disabled,
            threads,
            |id, prepared| {
                let job = Job {
                    at,
                    id,
                    prepared: prepared.map(Moved::new),
                };
                at += 1;
                // A send fails only once every worker has stopped (one
                // panicked): the scope's end reports it.
                let _ = jobs.send(job);
                for (at, result) in results.try_iter() {
                    in_order.add(at, result, &mut ready);
                }
            },
        );
        drop(jobs);
        for (at, result) in results {
            in_order.add(at, result, &mut ready);
        }
    });
}

/// A function handed over to [`stream_parallel`]'s workers.
struct Job {
    /// Its place in the order of handing over.
    at: usize,
    /// The function.
    id: FunctionId,
    /// Its L1, or why there is none.
    prepared: Result<Moved, String>,
}

/// A function's [`Prepared`] L1 as it moves to a worker thread: its
/// analyses ([`Facts`]) out of the [`Rc`]s one thread shares them in.
pub(super) struct Moved {
    /// The L1 function after the L1 passes.
    l1: Function,
    /// The counts of the L1 passes, by name.
    passes: Vec<(&'static str, PassStats)>,
    /// How many times each L1 analysis was computed, by type name.
    analyses: Vec<(&'static str, usize)>,
    /// Its constant propagation.
    constants: Constants,
    /// Its stack.
    stack: Stack,
    /// Its dominator tree.
    dominators: Dominators,
}

impl Moved {
    /// `prepared`, its analyses taken out of their [`Rc`]s (copied only
    /// where something else still holds one).
    pub(super) fn new(prepared: Prepared) -> Self {
        let Prepared {
            l1,
            facts,
            passes,
            analyses,
        } = prepared;
        let Facts {
            constants,
            stack,
            dominators,
            ..
        } = facts;
        Self {
            l1,
            passes,
            analyses,
            constants: Rc::unwrap_or_clone(constants),
            stack: Rc::unwrap_or_clone(stack),
            dominators: Rc::unwrap_or_clone(dominators),
        }
    }

    /// The function as it was [`Prepared`].
    pub(super) fn prepared(self) -> Prepared {
        Prepared {
            l1: self.l1,
            facts: Facts::new(
                Rc::new(self.constants),
                Rc::new(self.stack),
                Rc::new(self.dominators),
            ),
            passes: self.passes,
            analyses: self.analyses,
        }
    }
}

/// The next function in `queue`, if the stream has not ended.
fn next(queue: &Mutex<Receiver<Job>>) -> Option<Job> {
    queue
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .recv()
        .ok()
}

/// Each of the functions `order` of `program` (recovered from `image`,
/// with `summaries`) in L1 ([`decompile_l1`], the passes `disabled`),
/// handed to `visit` in that order, on this thread. With more than one
/// thread, `threads` workers lift them ahead of `visit` (a function's L1
/// reads only the finished summaries, never what `visit` does), at most
/// [`AHEAD`] per thread beyond the last visited, so only those are held;
/// `visit` sees the same functions in the same order either way.
pub(super) fn lifted(
    image: &Image<'_>,
    program: &Program,
    order: &[FunctionId],
    summaries: &Summaries,
    disabled: &[String],
    threads: usize,
    mut visit: impl FnMut(FunctionId, Result<Prepared, String>),
) {
    if threads <= 1 {
        for &id in order {
            visit(id, decompile_l1(image, program, id, summaries, disabled));
        }
        return;
    }
    let ahead = threads.saturating_mul(AHEAD);
    let taken = AtomicUsize::new(0);
    let window = Window::default();
    let (done, results) = mpsc::channel();
    thread::scope(|scope| {
        for _ in 0..threads {
            let (taken, window, done) = (&taken, &window, done.clone());
            scope.spawn(move || {
                let _stop = Stop(window);
                loop {
                    let at = taken.fetch_add(1, Ordering::Relaxed);
                    let Some(&id) = order.get(at) else {
                        break;
                    };
                    if !window.wait(at.saturating_sub(ahead)) {
                        break;
                    }
                    let prepared = decompile_l1(image, program, id, summaries, disabled);
                    if done.send((at, prepared.map(Moved::new))).is_err() {
                        break;
                    }
                }
            });
        }
        drop(done);
        let _stop = Stop(&window);
        let mut waiting = BTreeMap::new();
        for (at, &id) in order.iter().enumerate() {
            let prepared = loop {
                if let Some(prepared) = waiting.remove(&at) {
                    break prepared;
                }
                // Every worker stopped before lifting it: one panicked,
                // which the scope's end reports.
                let Ok((place, prepared)) = results.recv() else {
                    return;
                };
                waiting.insert(place, prepared);
            };
            visit(id, prepared.map(Moved::prepared));
            window.advance(at + 1);
        }
    });
}

/// How many functions per thread [`lifted`] lifts ahead of those visited.
const AHEAD: usize = 4;

/// How many functions [`lifted`] has visited, for its workers to wait on;
/// or that it stopped (a thread panicked).
#[derive(Default)]
struct Window {
    /// The functions visited, and whether lifting stopped.
    state: Mutex<(usize, bool)>,
    /// Signalled when either changes.
    changed: Condvar,
}

impl Window {
    /// Waits until at least `visited` functions are visited: true, or
    /// lifting stopped: false.
    fn wait(&self, visited: usize) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while state.0 < visited && !state.1 {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        !state.1
    }

    /// `visited` functions are visited.
    fn advance(&self, visited: usize) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).0 = visited;
        self.changed.notify_all();
    }
}

/// Stops [`lifted`]'s workers if the thread holding it panics, so none
/// waits on a [`Window`] that no longer moves.
struct Stop<'w>(&'w Window);

impl Drop for Stop<'_> {
    fn drop(&mut self) {
        if thread::panicking() {
            self.0
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .1 = true;
            self.0.changed.notify_all();
        }
    }
}

/// Results put back in order: each handed on once those before it are.
struct InOrder<T> {
    /// The place of the next result to hand on.
    next: usize,
    /// Results that came before those ahead of them, by place.
    waiting: BTreeMap<usize, T>,
}

impl<T> Default for InOrder<T> {
    fn default() -> Self {
        Self {
            next: 0,
            waiting: BTreeMap::new(),
        }
    }
}

impl<T> InOrder<T> {
    /// Takes `result`, at place `at`, and hands to `ready` every result now
    /// in order.
    fn add(&mut self, at: usize, result: T, ready: &mut impl FnMut(T)) {
        self.waiting.insert(at, result);
        while let Some(result) = self.waiting.remove(&self.next) {
            ready(result);
            self.next += 1;
        }
    }
}

/// The interface and callees of a function `prepared` in L1
/// ([`lowering::interface`]), with the interfaces `known`.
///
/// # Errors
///
/// Lowering fails.
pub(super) fn interface(
    image: &Image<'_>,
    prepared: &Prepared,
    prototypes: &dyn Prototypes,
    data: &dyn Data,
    known: &Interfaces,
) -> Result<Found, String> {
    with_context(
        image,
        prepared.l1.entry,
        known,
        prototypes,
        data,
        |context| {
            lowering::interface(&prepared.l1, &prepared.facts, context).map_err(|e| e.to_string())
        },
    )
}

/// [`interface`], and the function's scheme ([`lowering::summarise`]),
/// with the interfaces and schemes `known`; where it makes a `futex` call
/// its code does not settle, its interface under the reading view's
/// assumption too ([`Found::assumed`](lowering::Found::assumed)).
///
/// # Errors
///
/// Lowering fails.
pub(super) fn summarise(
    image: &Image<'_>,
    prepared: &Prepared,
    prototypes: &dyn Prototypes,
    data: &dyn Data,
    known: &Interfaces,
) -> Result<(Found, Option<Summary>), String> {
    with_context(
        image,
        prepared.l1.entry,
        known,
        prototypes,
        data,
        |context| {
            let (mut found, summary) = lowering::summarise(&prepared.l1, &prepared.facts, context)
                .map_err(|e| e.to_string())?;
            if found.unsettled_futex && !context.assume_futex {
                let assumed = Context {
                    assume_futex: true,
                    ..*context
                };
                found.assumed = lowering::interface(&prepared.l1, &prepared.facts, &assumed)
                    .ok()
                    .map(Box::new);
            }
            Ok((found, summary))
        },
    )
}
