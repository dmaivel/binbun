//! Call sites as the session shows them ([`CallSite`]): each call of the
//! call graph ([`binbun::calls`]) with the C line making it, from the
//! caller's document (the user's names printed), and what is known of its
//! arguments there ([`binbun::calls::sites`]). A function's callers and
//! callees are answered as [`Question::Callers`](crate::Question::Callers)
//! and [`Question::Callees`](crate::Question::Callees), the callers'
//! documents made on several threads.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;

use binbun::Database;
use binbun::calls::Call;
use binbun::calls::sites::{Known, Site, sites};
use binbun::cfg::FunctionId;
use binbun::decompile::View;
use binbun_ast::ir::Node;

use crate::document::Document;
use crate::worker::{Shared, document};

/// The most threads making callers' documents at once.
const THREADS: usize = 8;

/// A call site with what its caller's C shows of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallSite {
    /// The call.
    pub call: Call,
    /// The C line making it (trimmed), if the caller decompiles and a
    /// line stands for the call.
    pub line: Option<String>,
    /// What is known of each argument there (none if the C has no such
    /// call).
    pub arguments: Vec<Known>,
}

/// `calls` (sorted by caller) with their callers' C lines and arguments
/// in `view`; `None` if `cancel` was set.
pub(crate) fn call_sites(
    shared: &Shared,
    database: &Database<'_>,
    calls: &[Call],
    view: View,
    cancel: &AtomicBool,
) -> Option<Vec<CallSite>> {
    let mut by_caller: BTreeMap<FunctionId, Vec<Call>> = BTreeMap::new();
    for &call in calls {
        by_caller.entry(call.caller).or_default().push(call);
    }
    let groups: Vec<Vec<Call>> = by_caller.into_values().collect();
    let next = AtomicUsize::new(0);
    let done: Mutex<Vec<(usize, Vec<CallSite>)>> = Mutex::new(Vec::new());
    let threads = thread::available_parallelism()
        .map_or(1, usize::from)
        .min(THREADS)
        .min(groups.len());
    thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(group) = groups.get(index) else {
                        return;
                    };
                    if cancel.load(Ordering::Relaxed) || shared.cancelled() {
                        return;
                    }
                    let made = of_caller(shared, database, group, view);
                    done.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push((index, made));
                }
            });
        }
    });
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
    let mut done = done.into_inner().unwrap_or_else(PoisonError::into_inner);
    done.sort_unstable_by_key(|&(index, _)| index);
    Some(done.into_iter().flat_map(|(_, made)| made).collect())
}

/// The calls of one caller (`group`) with its C lines and arguments.
fn of_caller(
    shared: &Shared,
    database: &Database<'_>,
    group: &[Call],
    view: View,
) -> Vec<CallSite> {
    let Some(caller) = group.first().map(|call| call.caller) else {
        return Vec::new();
    };
    let printed = document(shared, database, caller, view);
    let found = printed.as_ref().ok().map(|document| {
        let at: Vec<u64> = group.iter().map(|call| call.site).collect();
        sites(&document.decompiled.l2, &at)
    });
    group
        .iter()
        .enumerate()
        .map(|(i, &call)| {
            let site = found.as_ref().and_then(|found| found.get(i)?.as_ref());
            let line = match (&printed, site) {
                (Ok(document), Some(site)) => line(document, site),
                _ => None,
            };
            CallSite {
                call,
                line,
                arguments: site.map(|site| site.arguments.clone()).unwrap_or_default(),
            }
        })
        .collect()
}

/// The line of `document` standing for `site`: the first token of its
/// node, else of its statement.
fn line(document: &Document, site: &Site) -> Option<String> {
    let text = &document.text;
    let start = [site.node, Node::Stmt(site.statement)]
        .iter()
        .find_map(|&node| {
            document
                .spans
                .iter()
                .find(|span| span.node == Some(node))
                .map(|span| span.range.start)
        })?;
    let before = text.get(..start)?;
    let from = before.rfind('\n').map_or(0, |i| i + 1);
    let to = text
        .get(start..)?
        .find('\n')
        .map_or(text.len(), |i| start + i);
    text.get(from..to).map(|line| line.trim().to_owned())
}
