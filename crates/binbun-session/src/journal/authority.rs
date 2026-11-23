//! Rights judged when a change is applied (sync §4.2): the journal asks
//! an [`Authority`] (collab's, from the membership chain) immediately
//! before it takes a change from outside its log, under the same lock,
//! and gets one of three verdicts. A [`Verdict::Never`] freezes the
//! change's chain for good, so it rests only on the change's own bytes,
//! its chain and the membership chain; rules about a change on another
//! chain are never a verdict (the op is inert in the projection instead).
//!
//! A chain has one role, for good: that of the membership record its
//! start names (its grant, [`super::Under`]). So a role refusal is always
//! a [`Verdict::Never`], and the only wait on membership is a start's,
//! for its grant's record ([`Verdict::Decline`]).

use std::fmt;

use super::{Body, ChangeId, Head, PublicKey};

/// The most bytes of a reason told with a refusal.
pub const MAX_WHY: usize = 512;

/// What may be decided of a change.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// It is taken.
    Admit,
    /// Not now: it is not kept, and its chain stops until what is named
    /// changes (a start, whose chain is not known, is declined instead).
    NotYet(Cause),
    /// Not now, and no stop: a start whose grant's record is not here
    /// yet, or of an author past a local guard. It is declined on the
    /// link it came by and asked for again when the membership chain grows
    /// or a chain of its author freezes.
    Decline,
    /// Never: its chain freezes from it, its signed head kept.
    Never(Why),
}

/// What a chain stopped by [`Verdict::NotYet`] (or held) waits for: a
/// stop is made only on a chain known, from a body that opened and
/// matched its head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cause {
    /// This change, which one of its ops names.
    Change(ChangeId),
    /// The link of this view-only author, linked here with another build,
    /// to end or change build.
    ViewOnly(PublicKey),
}

/// Why a change is refused for good: at most [`MAX_WHY`] bytes, cut where
/// it is made.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Why(String);

impl Why {
    /// `text`, cut to [`MAX_WHY`] bytes at a character's boundary.
    pub fn new(text: &str) -> Self {
        let mut end = text.len().min(MAX_WHY);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        Self(text.get(..end).unwrap_or_default().to_owned())
    }

    /// Its text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Why {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Why {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Why({:?})", self.0)
    }
}

/// Who may write what in a share, as its membership chain says.
pub trait Authority: Send + Sync {
    /// Whether the change `head`, `body` of `author` (its chain's author),
    /// on a chain whose start names membership record `grant`, is taken
    /// now. Called with the change's own checks passed (its link,
    /// signature, commitment, structure and binding), for every change
    /// from outside the local log, immediately before it is taken.
    fn admit(&self, author: PublicKey, grant: u64, head: &Head, body: &Body) -> Verdict;

    /// Whether the membership chain names `author` now or named it before
    /// (a removed member included): who may have a chain known here.
    fn knows(&self, author: PublicKey) -> bool;

    /// The number of the membership record that set `author`'s entry as
    /// it stands, if it gives them a role now: what a chain they begin now
    /// names as its grant.
    fn grant(&self, author: PublicKey) -> Option<u64>;

    /// Whether a verdict given now can be trusted for this author's own
    /// commits (sync §4.5 rule 6): a link is a reader's, so the membership
    /// chain is no older than one peer's. Without one, a commit is written
    /// pending unless the chain already makes it final (`Never`).
    fn reader(&self) -> bool;
}

/// Why a chain is frozen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrozenBy {
    /// A membership record (its number and hash) cut its author's writing.
    Cut {
        /// The record's number.
        record: u64,
        /// The record's hash.
        hash: [u8; 32],
    },
    /// Its author signed two changes for one place ([`super::ForkProof`]).
    Fork,
    /// A change of it was refused for good ([`Verdict::Never`]).
    Never,
}

impl fmt::Display for FrozenBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cut { record, .. } => {
                write!(f, "its author's membership was cut by record {record}")
            }
            Self::Fork => f.write_str("its chain equivocates: two changes at one place"),
            Self::Never => f.write_str("a change of it was refused for good"),
        }
    }
}
