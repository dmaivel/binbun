//! How far a whole-program pass has got, for a front end to show while it
//! runs ([`Progress`]): the functions done of those the pass works
//! through. A [`Database`](crate::Database) has one
//! ([`Database::progress`](crate::Database::progress)) that its passes
//! (the references, each pass finding what callers read) start and step.

use std::sync::atomic::{AtomicUsize, Ordering};

/// The functions a pass has done of its `total`, read from any thread
/// while the pass runs; a new pass starts it again.
#[derive(Debug, Default)]
pub struct Progress {
    done: AtomicUsize,
    total: AtomicUsize,
}

impl Progress {
    /// A new pass, of `total` functions, none done.
    pub fn start(&self, total: usize) {
        self.done.store(0, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
    }

    /// One more function done.
    pub fn step(&self) {
        self.done.fetch_add(1, Ordering::Relaxed);
    }

    /// The functions done and the pass's total; `None` before any pass
    /// starts. Done never reads above the total.
    pub fn get(&self) -> Option<(usize, usize)> {
        let total = self.total.load(Ordering::Relaxed);
        (total > 0).then(|| (self.done.load(Ordering::Relaxed).min(total), total))
    }
}
