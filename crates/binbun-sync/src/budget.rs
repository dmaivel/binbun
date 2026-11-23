//! What the machine draws from the caller's budgets (sync §3.5), and the
//! instruments that count its work.
//!
//! The machine charges the state it keeps for a link (`sync.link`) as it
//! grows and refunds it as it shrinks; a charge refused closes the link.
//! Everything else it does is reported as [`Work`], so that a caller can
//! meter it and a test can check each message's work against the cost
//! table ([`Counting`]). Frames, pages and rates are the caller's: a page
//! of changes or records is built only when the caller serves a
//! [`crate::Job`], holding a page permit.

use std::collections::BTreeMap;

use crate::machine::LinkId;

/// What the machine charges for one chain a link names: its told tip and
/// the task scheduled for it, measured at about 330 bytes of heap with
/// their maps' nodes (`tests/memory.rs`; the design's estimate was 250).
pub const PER_CHAIN: usize = 384;

/// What the machine charges for one chain a link has declined (sync
/// §4.4): an entry of its `declined` set, kept past a reset of what the
/// link told, with its map node.
pub const PER_DECLINED: usize = 64;

/// One unit of work, as the cost table counts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Work {
    /// A signature checked (a head of a `Heads` reply, a proof taken).
    Verify,
    /// An envelope given to the journal to judge and apply (at most one
    /// signature check, one opening and one application).
    Admit,
    /// Items read from the journal by point lookup or page.
    Read(usize),
    /// Heads hashed.
    Hash(usize),
    /// A request made.
    Request,
    /// A task made.
    Task,
    /// A task ended.
    TaskEnded,
    /// Bytes of envelopes or records served in a page.
    Served(usize),
}

/// The budgets the machine draws from. `binbun-collab`'s `Budgets`
/// implements it over its permits; [`Counting`] counts for tests.
pub trait Budget {
    /// Charges `bytes` more of `sync.link` to `link`; false if a ceiling
    /// (the link's or the process's) would be passed, and the link is
    /// then closed.
    fn charge(&mut self, link: LinkId, bytes: usize) -> bool;

    /// Gives back `bytes` of `link`'s charge.
    fn refund(&mut self, link: LinkId, bytes: usize);

    /// `work` done for `link` (none: for no link in particular).
    fn spend(&mut self, link: Option<LinkId>, work: Work);
}

/// Work spent, by kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Spent {
    /// Signatures checked.
    pub verify: usize,
    /// Envelopes judged.
    pub admit: usize,
    /// Items read.
    pub read: usize,
    /// Heads hashed.
    pub hash: usize,
    /// Requests made.
    pub request: usize,
    /// Tasks made.
    pub task: usize,
    /// Tasks ended.
    pub task_ended: usize,
    /// Bytes served.
    pub served: usize,
}

impl Spent {
    /// Adds `work`.
    pub fn add(&mut self, work: Work) {
        let (total, n) = match work {
            Work::Verify => (&mut self.verify, 1),
            Work::Admit => (&mut self.admit, 1),
            Work::Read(n) => (&mut self.read, n),
            Work::Hash(n) => (&mut self.hash, n),
            Work::Request => (&mut self.request, 1),
            Work::Task => (&mut self.task, 1),
            Work::TaskEnded => (&mut self.task_ended, 1),
            Work::Served(n) => (&mut self.served, n),
        };
        *total = total.saturating_add(n);
    }
}

/// Counts what is charged and spent, with a ceiling per link: the
/// instrument of the work properties (P4).
#[derive(Clone, Debug)]
pub struct Counting {
    /// The most bytes charged to one link.
    pub ceiling: usize,
    /// Bytes charged now, per link.
    pub charged: BTreeMap<LinkId, usize>,
    /// Work spent since [`Self::take`] was last called.
    pub spent: Spent,
    /// The most charged to one link at any time.
    pub peak: usize,
}

impl Counting {
    /// One whose links may each be charged `ceiling` bytes.
    pub fn new(ceiling: usize) -> Self {
        Self {
            ceiling,
            charged: BTreeMap::new(),
            spent: Spent::default(),
            peak: 0,
        }
    }

    /// The work spent since the last call, forgotten (not the charges).
    pub fn take(&mut self) -> Spent {
        std::mem::take(&mut self.spent)
    }
}

impl Default for Counting {
    /// One with the design's per-link ceiling of `sync.link`: 32 MiB.
    fn default() -> Self {
        Self::new(32 << 20)
    }
}

impl Budget for Counting {
    fn charge(&mut self, link: LinkId, bytes: usize) -> bool {
        let charged = self.charged.entry(link).or_default();
        match charged
            .checked_add(bytes)
            .filter(|&total| total <= self.ceiling)
        {
            Some(total) => {
                *charged = total;
                self.peak = self.peak.max(total);
                true
            }
            None => false,
        }
    }

    fn refund(&mut self, link: LinkId, bytes: usize) {
        if let Some(charged) = self.charged.get_mut(&link) {
            *charged = charged.saturating_sub(bytes);
            if *charged == 0 {
                self.charged.remove(&link);
            }
        }
    }

    fn spend(&mut self, _: Option<LinkId>, work: Work) {
        self.spent.add(work);
    }
}
