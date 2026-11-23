//! What functions do to registers and the stack ([`summarize`]), each
//! computed after the functions it calls ([`callees_first`]) so that its
//! calls take their callees' effects.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::sync::mpsc;
use std::sync::{Condvar, Mutex, PoisonError};
use std::thread;

use binbun_loader::Image;
use binbun_semantics::core::Id as _;
use binbun_ssa::Function;
use binbun_ssa::constant::{Constants, propagate};
use binbun_ssa::stack::Stack;
use binbun_ssa::summary::{Summary, summarize};

use crate::cfg::{Destination, Exit, FunctionId, Program};
use crate::lift::{ImageEnvironment, SsaError, lift_function};
use crate::memory::ImageMemory;

/// Function effects, by entry.
pub type Summaries = BTreeMap<u64, Summary>;

/// The effects of the functions of `program` (recovered from `image`) that
/// have one ([`summarize`]), callees first so that callers use them; in a
/// cycle of calls, the first reached takes the calling convention for the
/// others.
pub fn summaries(image: &Image<'_>, program: &Program) -> Summaries {
    let mut summaries = Summaries::new();
    summarize_each(image, program, callees_first(program), &mut summaries);
    summaries
}

/// Adds the effect of each of `functions` of `program` (recovered from
/// `image`) that has one to `summaries`, in order, each built with the
/// effects in `summaries` by then.
pub fn summarize_each(
    image: &Image<'_>,
    program: &Program,
    functions: impl IntoIterator<Item = FunctionId>,
    summaries: &mut Summaries,
) {
    summarize_each_with(image, program, functions, summaries, |_, _| {});
}

/// [`summarize_each`], handing each function to `visit` as it is visited:
/// its L1 (built with the effects in `summaries` by then) and constant
/// propagation over it, or why it does not lift. So a whole-program
/// analysis over L1 lifts each function once, with the summaries.
pub fn summarize_each_with(
    image: &Image<'_>,
    program: &Program,
    functions: impl IntoIterator<Item = FunctionId>,
    summaries: &mut Summaries,
    mut visit: impl FnMut(FunctionId, Result<(&Function, &Constants), SsaError>),
) {
    let memory = ImageMemory::new(image);
    let Ok(convention) = ImageEnvironment::new(image, &[]) else {
        return;
    };
    for function in functions {
        let (_, effect) = summarize_one(
            image,
            program,
            &memory,
            &convention,
            function,
            summaries,
            &mut visit,
        );
        if let Some((entry, summary)) = effect {
            summaries.insert(entry, summary);
        }
    }
}

/// Function `function` of `program` (recovered from `image`, read through
/// `memory`, under `convention`) lifted with the effects in `summaries`,
/// handed to `visit` with its constant propagation (or why it does not
/// lift; not at all if it is no function of `program`), and its entry
/// with its effect, if it has one.
fn summarize_one<T>(
    image: &Image<'_>,
    program: &Program,
    memory: &ImageMemory<'_>,
    convention: &ImageEnvironment,
    function: FunctionId,
    summaries: &Summaries,
    visit: impl FnOnce(FunctionId, Result<(&Function, &Constants), SsaError>) -> T,
) -> (Option<T>, Option<(u64, Summary)>) {
    let built = match lift_function(image, program, function, summaries) {
        Ok(built) => built,
        Err(error) => return (Some(visit(function, Err(error))), None),
    };
    let Some(entry) = program.functions.get(function).map(|f| f.entry) else {
        return (None, None);
    };
    let (declarations, stack_pointer) = (convention.declarations(), convention.stack_pointer());
    let constants = propagate(&built, memory);
    let visited = visit(function, Ok((&built, &constants)));
    let stack = Stack::new(
        &built,
        declarations,
        &constants,
        stack_pointer,
        &convention.arguments(),
    );
    let effect = summarize(&built, declarations, &constants, &stack, stack_pointer);
    (Some(visited), effect.map(|summary| (entry, summary)))
}

/// The effects of the functions of `program` (recovered from `image`), as
/// [`summaries`] finds them, with what `visit` makes of each function's L1
/// (as [`summarize_each_with`] hands it over) handed to `collect` in the
/// order of [`callees_first`]; on `threads` threads.
///
/// Lifting a function reads only the effects of the functions it calls
/// directly ([`calls`]) that come before it in that order (one after it
/// is in a cycle with it, and takes the convention's effect), so each
/// function is lifted once those are known, with those alone: the
/// effects, and `visit`'s results, are those of one thread, whatever the
/// threads.
pub fn summarize_all<T: Send>(
    image: &Image<'_>,
    program: &Program,
    threads: usize,
    visit: impl Fn(FunctionId, Result<(&Function, &Constants), SsaError>) -> T + Sync,
    mut collect: impl FnMut(FunctionId, T),
) -> Summaries {
    let order = callees_first(program);
    let mut summaries = Summaries::new();
    if threads <= 1 {
        summarize_each_with(image, program, order, &mut summaries, |id, built| {
            collect(id, visit(id, built));
        });
        return summaries;
    }
    let Ok(convention) = ImageEnvironment::new(image, &[]) else {
        return summaries;
    };
    let schedule = Schedule::new(program, &order);
    let (done, results) = mpsc::channel();
    thread::scope(|scope| {
        for _ in 0..threads {
            let (schedule, done, visit, convention) =
                (&schedule, done.clone(), &visit, &convention);
            let order = &order;
            scope.spawn(move || {
                let _stop = Stop(schedule);
                let memory = ImageMemory::new(image);
                while let Some((at, known)) = schedule.next() {
                    let Some(&function) = order.get(at) else {
                        break;
                    };
                    let (visited, effect) =
                        summarize_one(image, program, &memory, convention, function, &known, visit);
                    schedule.finish(at, effect);
                    if done.send((at, visited)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(done);
        let _stop = Stop(&schedule);
        let mut waiting = BTreeMap::new();
        for (at, &function) in order.iter().enumerate() {
            let visited = loop {
                if let Some(visited) = waiting.remove(&at) {
                    break visited;
                }
                // Every worker stopped before it: one panicked, which the
                // scope's end reports.
                let Ok((place, visited)) = results.recv() else {
                    return;
                };
                waiting.insert(place, visited);
            };
            if let Some(visited) = visited {
                collect(function, visited);
            }
        }
    });
    schedule.into_summaries()
}

/// Which functions [`summarize_all`] may lift next: those whose earlier
/// callees' effects are known.
struct Schedule {
    /// Per place in the order: the places of its callees before it.
    earlier: Vec<Vec<usize>>,
    /// Per place in the order: the places of the functions after it that
    /// call it.
    later: Vec<Vec<usize>>,
    /// The entry of the function at each place.
    entries: Vec<Option<u64>>,
    /// What changes as functions are lifted.
    state: Mutex<Progress>,
    /// Signalled when a function is ready or lifting stops.
    changed: Condvar,
}

/// [`Schedule`]'s state.
struct Progress {
    /// The places whose earlier callees are all known, smallest first.
    ready: BinaryHeap<Reverse<usize>>,
    /// Per place: how many of its earlier callees are not known yet.
    waiting: Vec<usize>,
    /// How many functions are not taken yet.
    left: usize,
    /// The effects known, by entry.
    summaries: Summaries,
    /// Whether lifting stopped (a thread panicked).
    stopped: bool,
}

impl Schedule {
    /// The schedule of the functions of `program` in `order`.
    fn new(program: &Program, order: &[FunctionId]) -> Self {
        let mut place = vec![usize::MAX; program.functions.len()];
        for (at, id) in order.iter().enumerate() {
            if let Some(slot) = place.get_mut(id.index()) {
                *slot = at;
            }
        }
        let mut earlier = Vec::with_capacity(order.len());
        let mut later = vec![Vec::new(); order.len()];
        for (at, &id) in order.iter().enumerate() {
            let mut before: Vec<usize> = calls(program, id)
                .into_iter()
                .filter_map(|callee| place.get(callee.index()).copied())
                .filter(|&callee| callee < at)
                .collect();
            before.sort_unstable();
            before.dedup();
            for &callee in &before {
                if let Some(list) = later.get_mut(callee) {
                    list.push(at);
                }
            }
            earlier.push(before);
        }
        let waiting: Vec<usize> = earlier.iter().map(Vec::len).collect();
        let ready = waiting
            .iter()
            .enumerate()
            .filter(|&(_, &count)| count == 0)
            .map(|(at, _)| Reverse(at))
            .collect();
        Self {
            earlier,
            later,
            entries: order
                .iter()
                .map(|&id| program.functions.get(id).map(|f| f.entry))
                .collect(),
            state: Mutex::new(Progress {
                ready,
                waiting,
                left: order.len(),
                summaries: Summaries::new(),
                stopped: false,
            }),
            changed: Condvar::new(),
        }
    }

    /// The next function to lift (its place), with the effects of its
    /// earlier callees; none once every function is taken or lifting
    /// stopped.
    fn next(&self) -> Option<(usize, Summaries)> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if state.stopped || state.left == 0 {
                return None;
            }
            if let Some(Reverse(at)) = state.ready.pop() {
                state.left -= 1;
                let known = self
                    .earlier
                    .get(at)
                    .into_iter()
                    .flatten()
                    .filter_map(|&callee| {
                        let entry = (*self.entries.get(callee)?)?;
                        Some((entry, state.summaries.get(&entry)?.clone()))
                    })
                    .collect();
                return Some((at, known));
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// The function at `at` is lifted, with `effect` (its entry and
    /// effect, if it has one).
    fn finish(&self, at: usize, effect: Option<(u64, Summary)>) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((entry, summary)) = effect {
            state.summaries.insert(entry, summary);
        }
        for &caller in self.later.get(at).into_iter().flatten() {
            let Some(count) = state.waiting.get_mut(caller) else {
                continue;
            };
            *count -= 1;
            if *count == 0 {
                state.ready.push(Reverse(caller));
            }
        }
        drop(state);
        self.changed.notify_all();
    }

    /// The effects found.
    fn into_summaries(self) -> Summaries {
        self.state
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .summaries
    }
}

/// Stops [`summarize_all`]'s workers if the thread holding it panics, so
/// none waits for a function that will not be ready.
struct Stop<'s>(&'s Schedule);

impl Drop for Stop<'_> {
    fn drop(&mut self) {
        if thread::panicking() {
            self.0
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .stopped = true;
            self.0.changed.notify_all();
        }
    }
}

/// The functions of `program` that function `id` calls directly, in the
/// order of its blocks: those whose effects its L1 takes.
pub fn calls(program: &Program, id: FunctionId) -> Vec<FunctionId> {
    let Some(function) = program.functions.get(id) else {
        return Vec::new();
    };
    function
        .blocks
        .iter()
        .filter_map(|&block| match program.blocks.get(block)?.exit {
            Exit::Call {
                callee: Destination::Address(target),
                ..
            } => program.function_at(target),
            Exit::Call { .. }
            | Exit::Next
            | Exit::Jump(_)
            | Exit::Branch(_)
            | Exit::Return
            | Exit::Stop
            | Exit::Invalid
            | Exit::Limit => None,
        })
        .collect()
}

/// The functions of `program`, each after the functions it calls directly
/// ([`calls`]; but in cycles), without recursion.
pub fn callees_first(program: &Program) -> Vec<FunctionId> {
    let mut order = Vec::new();
    let mut seen = BTreeSet::new();
    for (root, _) in &program.functions {
        if !seen.insert(root) {
            continue;
        }
        let mut stack = vec![(root, calls(program, root), 0usize)];
        while let Some((id, list, next)) = stack.last_mut() {
            if let Some(&callee) = list.get(*next) {
                *next += 1;
                if seen.insert(callee) {
                    let list = calls(program, callee);
                    stack.push((callee, list, 0));
                }
            } else {
                order.push(*id);
                stack.pop();
            }
        }
    }
    order
}
