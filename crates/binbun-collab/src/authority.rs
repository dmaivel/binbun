//! The journal's [`Authority`] over the membership chain (sync §4.2):
//! what a share's journal asks immediately before it takes a change from
//! outside its log, and of this install's own commits while collaboration
//! is attached.
//!
//! - **The membership chain** decides first ([`Membership::judge`]): the
//!   role of the grant the chain's start names, and where a later record
//!   closed the chain. A `Never` rests on nothing else; the only wait on
//!   membership is a start's, for its grant's record.
//! - **The engine rule**, local by decision: a change of another build
//!   than this one, by an author linked here view-only (another build),
//!   is not taken while that link lasts ([`Cause::ViewOnly`]); it is when
//!   it comes again after.
//! - **A local guard** of chains per author in this journal (one binary):
//!   a start past an author's [`MAX_CHAINS_PER_AUTHOR`] chains is not
//!   taken ([`Verdict::Decline`]: declined on its link, asked for again
//!   once a chain of theirs freezes). It is no rule replicas agree on.
//!
//! The judge keeps its own copy of the chain behind its own lock: the
//! journal calls it under the session's lock, while the peer's state may
//! be locked by the caller of the session.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use binbun_session::journal::{
    Authority, Body, Cause, ChainId, EngineVersion, Head, PublicKey, Verdict,
};

use crate::membership::{Membership, Writes};

/// The most chains one author's edits are taken on in one journal (one
/// binary): a local guard (sync §3.5).
pub const MAX_CHAINS_PER_AUTHOR: usize = 64;

/// What the judge goes by.
struct Rules {
    membership: Membership,
    engine: EngineVersion,
    /// The authors linked here view-only (another build).
    view_only: BTreeSet<PublicKey>,
    /// Per author, the chains whose starts were taken.
    chains: BTreeMap<PublicKey, BTreeSet<ChainId>>,
    /// Whether a link is a reader's: this author's own commits are judged
    /// at once only then.
    reader: bool,
}

/// The membership chain as the journal's authority.
pub(crate) struct Judge(Mutex<Rules>);

impl Judge {
    /// One going by `membership`, this install's build `engine`.
    pub(crate) fn new(membership: Membership, engine: EngineVersion) -> Self {
        Self(Mutex::new(Rules {
            membership,
            engine,
            view_only: BTreeSet::new(),
            chains: BTreeMap::new(),
            reader: false,
        }))
    }

    fn rules(&self) -> MutexGuard<'_, Rules> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Goes by `membership` from now.
    pub(crate) fn set_membership(&self, membership: Membership) {
        self.rules().membership = membership;
    }

    /// A judge of its own going by `membership`, with this one's other
    /// rules as they are now: what a membership record being taken makes
    /// of pending work, judged before the record is published and seen by
    /// no other caller of this one (sync §4.3).
    pub(crate) fn candidate(&self, membership: Membership) -> Self {
        let rules = self.rules();
        Self(Mutex::new(Rules {
            membership,
            engine: rules.engine.clone(),
            view_only: rules.view_only.clone(),
            chains: rules.chains.clone(),
            reader: rules.reader,
        }))
    }

    /// Whether a link is a reader's from now.
    pub(crate) fn set_reader(&self, reader: bool) {
        self.rules().reader = reader;
    }

    /// Whether `author` is linked here view-only from now.
    pub(crate) fn set_view_only(&self, author: PublicKey, view_only: bool) {
        let mut rules = self.rules();
        if view_only {
            rules.view_only.insert(author);
        } else {
            rules.view_only.remove(&author);
        }
    }

    /// Counts `chain`, of `author`, as one whose start was taken (as the
    /// journal held it when collaboration attached).
    pub(crate) fn count(&self, author: PublicKey, chain: ChainId) {
        self.rules().chains.entry(author).or_default().insert(chain);
    }

    /// Counts `chain` no longer: frozen back to its start.
    pub(crate) fn forget(&self, chain: ChainId) {
        for chains in self.rules().chains.values_mut() {
            chains.remove(&chain);
        }
    }
}

impl Authority for Judge {
    fn admit(&self, author: PublicKey, grant: u64, head: &Head, body: &Body) -> Verdict {
        let mut rules = self.rules();
        let verdict = rules
            .membership
            .judge(author, head.chain, head.seq, grant, Writes::of(body));
        if verdict != Verdict::Admit {
            return verdict;
        }
        // A start writes nothing: the engine rule is about edits, and a
        // known chain's stop is woken when the view-only link ends.
        if head.seq > 1 && body.engine != rules.engine && rules.view_only.contains(&author) {
            return Verdict::NotYet(Cause::ViewOnly(author));
        }
        if head.seq == 1 {
            let chains = rules.chains.entry(author).or_default();
            if !chains.contains(&head.chain) {
                if chains.len() >= MAX_CHAINS_PER_AUTHOR {
                    return Verdict::Decline;
                }
                chains.insert(head.chain);
            }
        }
        Verdict::Admit
    }

    fn knows(&self, author: PublicKey) -> bool {
        self.rules().membership.members().contains_key(&author)
    }

    fn grant(&self, author: PublicKey) -> Option<u64> {
        self.rules().membership.grant(author)
    }

    fn reader(&self) -> bool {
        self.rules().reader
    }
}
