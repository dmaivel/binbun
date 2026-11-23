//! What the machine reads and writes outside itself (sync §3.1): the
//! journal of one share and binary, its membership chain (as opaque
//! records with their numbers and hashes), and the walk of listed
//! prefixes. The caller implements it over the journal and the
//! membership chain; `tests/model` holds an in-memory model.
//!
//! Everything here is a point lookup or a bounded page. Whatever needs an
//! authenticated head (a fork of either shape, a stop's head, a sealer)
//! comes back from the storage, which alone knows each chain's author and
//! holds the keys: the machine builds no proof itself.
//!
//! Every check of a change is made by [`Storage::admit`], whoever brings
//! it (sync §3.3): for a listed prefix, that the head's hash is the one
//! its walk checked at that number. The machine walks a listed prefix
//! before it pulls any of it, and compares nothing itself.

use binbun_session::journal::{
    Cause, ChainId, ChangeHash, ChangeId, ForkProof, ProjectId, PublicKey, SignedHead, Tip, Why,
};

use crate::envelope::Envelope;
use crate::wire::{Hash, Mark};

/// The most chains a page of tips looks at ([`Storage::tips_after`]),
/// whatever it finds among them.
pub const TIPS_SCAN: usize = 4096;

/// What became of one envelope given to [`Storage::admit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Admitted and applied (its start, if it was one: the chain is then
    /// known). [`Storage::events`] says the rest.
    Applied,
    /// The same change is held already.
    Same,
    /// Not taken: the chain, known here, is stopped at this head, which
    /// verified, and whose body opened and matched it. `cause` is a change
    /// awaited or a view-only link; nothing else makes a stop.
    Stopped {
        /// Why.
        cause: Cause,
        /// The signed head judged.
        head: Box<SignedHead>,
    },
    /// The chain is frozen at or below it; nothing taken.
    Frozen,
    /// Refused for good: the chain is frozen from it, durably, its head
    /// kept as local evidence.
    Never {
        /// Why.
        why: Why,
    },
    /// Its head and one held, both signed by the chain's author, are a
    /// fork; the proof is not yet taken.
    Fork(Box<ForkProof>),
    /// Not taken, and nothing stops: its head verified, but this sealing
    /// cannot be opened here (no key for the epoch it names, it does not
    /// open, or its body does not match the head), or it is a start not
    /// taken now (its grant's record not here yet, a local guard).
    /// Declined on the link it came by only.
    Declined,
    /// A start bound to another share or binary (and no prefix the
    /// genesis lists), or past a ceiling of known chains; or a change of
    /// a listed prefix past its listed number, or at or below it with no
    /// hash checked by the walk at its number equal to its head's: turned
    /// away with no state.
    TurnedAway,
    /// Its head does not verify: the source sent what no author signed.
    Invalid,
}

/// What became of a fork proof given to [`Storage::take_fork`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkTaken {
    /// Its chain is not known in this share: nothing kept.
    Unknown,
    /// It does not verify.
    Invalid,
    /// Kept, durably, and the chain frozen from its place, lower than any
    /// before.
    Lowered,
    /// A proof at its place or lower is held already.
    Held,
}

/// A page of membership records, or the record that differs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Records {
    /// The records after the asked number, in order, and whether more
    /// follow.
    Page {
        /// The records as signed.
        records: Vec<Vec<u8>>,
        /// Whether more follow.
        more: bool,
    },
    /// The record held at the asked number, whose hash is not the one
    /// asked.
    Diverged(Vec<u8>),
}

/// Why records were not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordsRefused {
    /// They do not follow the chain held: another record at a number held,
    /// or not the next number.
    Mismatch,
    /// They do not verify under the chain's signer, or break its bounds.
    Invalid,
}

/// What taking membership records changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Taken {
    /// The records taken (0 if every one was held already): if any, what
    /// was declined on each link is asked for again.
    pub records: u64,
}

/// A walk of a listed prefix's heads backwards from its pin (sync §3.3,
/// case C1), as far as it has been checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Walk {
    /// The lowest number checked; the walk is complete at 1.
    pub lowest: u64,
    /// The hash the head below it must have (its `prev`).
    pub next: ChangeHash,
}

/// What changed in the journal since [`Storage::events`] was last asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A change was admitted and applied: taken from a link, released
    /// from the held cache, or the user's own.
    Applied {
        /// The change.
        change: ChangeId,
        /// Its hash.
        hash: ChangeHash,
    },
    /// A chain became known in this share (its start was opened and
    /// found of it).
    Known(ChainId),
    /// A chain froze from this number (a fork, a `Never` or a cut).
    Frozen {
        /// The chain.
        chain: ChainId,
        /// The first number no longer kept.
        from: u64,
    },
}

/// The journal of one share and binary and its membership chain, as the
/// machine reads and writes them.
pub trait Storage {
    /// The share's genesis: the hash of its first record.
    fn genesis(&self) -> Hash;

    /// The membership chain's head.
    fn membership(&self) -> Mark;

    /// The hash of the record held at `seq`, if one is.
    fn record_hash(&self, seq: u64) -> Option<Hash>;

    /// Whether the membership chain names `key` a member now.
    fn is_member(&self, key: PublicKey) -> bool;

    /// Whether this side may send `Ready` to `remote` (sync §3.3 step 3):
    /// its chain names `remote` a member now, it holds the current key,
    /// and its session is on the binary the chain names.
    fn can_ready(&self, remote: PublicKey) -> bool;

    /// The records after `after`, whose hash should be `at`, within
    /// [`crate::wire::RECORDS`] records and
    /// [`crate::wire::RECORDS_BYTES`] bytes: an empty page if `after`
    /// is past the chain's end.
    fn records_after(&self, after: u64, at: Hash) -> Records;

    /// Takes `records`, which follow the record at `after`, one at a time
    /// (sync §4.3): each whole, with its freezes, before the next is
    /// looked at. A record that fails stops the page there and undoes
    /// none before it. What was taken, and why the rest was not if a
    /// record failed (they do not follow the chain held, or do not
    /// verify).
    fn take_records(
        &mut self,
        after: u64,
        records: &[&[u8]],
    ) -> (Taken, Result<(), RecordsRefused>);

    /// Whether the share is in recovery (a membership step not completed
    /// after its intent was durable, sync §4.3): it serves and takes
    /// nothing.
    fn recovering(&self) -> bool;

    /// The number and hash the share's first record lists for `chain`,
    /// if it lists it (sync §14.2). A listed prefix is the first record's
    /// for good: the storage turns away another head at a listed number
    /// (no fork), takes no proof of a listed chain, lets no cut reach
    /// into it, and takes a listed change on the record, its signature
    /// and its structure, not on its author's role. [`Storage::admit`]
    /// takes a change at or below the listed number only if a hash the
    /// walk checked at its number equals its head's, before its body is
    /// opened. The machine walks a listed prefix before it pulls any of
    /// it.
    fn listed(&self, chain: ChainId) -> Option<(u64, ChangeHash)>;

    /// This replica's own identity key.
    fn local(&self) -> PublicKey;

    /// `chain`'s tip, if it is known in this share.
    fn tip(&self, chain: ChainId) -> Option<Tip>;

    /// Up to `most` tips after `after` (exclusive), ascending by chain,
    /// of chains of `project` if one is given, from at most
    /// [`TIPS_SCAN`] chains looked at (sync §15, H6): the work is bounded by
    /// the chains scanned, not by the tips found, so the page may come
    /// back short or empty. With it, where the next page starts (the last
    /// chain looked at), unless none is left.
    fn tips_after(
        &self,
        after: Option<ChainId>,
        project: Option<ProjectId>,
        most: usize,
    ) -> (Vec<Tip>, Option<ChainId>);

    /// The admitted signed head at `seq` of `chain` (the start whatever
    /// is frozen after it).
    fn head_at(&self, chain: ChainId, seq: u64) -> Option<SignedHead>;

    /// The author of `chain`, if it is known.
    fn author(&self, chain: ChainId) -> Option<PublicKey>;

    /// The project `chain`'s start names as its origin, if it is known.
    fn origin(&self, chain: ChainId) -> Option<ProjectId>;

    /// Sealed envelopes of the admitted changes of `chain` after `after`
    /// (from the kept start at 0), at most `most` and `room` bytes, at
    /// least one if any; and whether more follow.
    fn changes_after(
        &mut self,
        chain: ChainId,
        after: u64,
        most: usize,
        room: usize,
    ) -> (Vec<Vec<u8>>, bool);

    /// `chain`'s fork proof, if one is held.
    fn evidence(&self, chain: ChainId) -> Option<ForkProof>;

    /// The first number of `chain` not kept, if it is frozen (a fork, a
    /// `Never` or a cut).
    fn frozen(&self, chain: ChainId) -> Option<u64>;

    /// Judges and, if admitted, applies `envelope` (sync §4.2), which
    /// came from `from`.
    fn admit(&mut self, from: PublicKey, envelope: &Envelope<'_>) -> Admission;

    /// Whether `head` is signed by the author of `chain` (which is
    /// known) and is of that chain.
    fn verify(&self, chain: ChainId, head: &SignedHead) -> bool;

    /// A fork proof from `theirs` and the head held at its number (first
    /// shape) or before it (second shape), if they are one; `theirs` is
    /// verified first.
    fn prove(&self, theirs: &SignedHead) -> Option<ForkProof>;

    /// A fork proof from `stopped`, a head this side verified and judged
    /// but did not admit (a stop's), and `theirs`, if they are one: for a
    /// chain known here and not listed, `theirs` verified under its
    /// author, the two at one number with different hashes, or at
    /// consecutive numbers with a `prev` that does not link.
    fn prove_pair(&self, stopped: &SignedHead, theirs: &SignedHead) -> Option<ForkProof>;

    /// Takes `proof` for a chain known in this share: persists it and
    /// freezes from its place, if lower.
    fn take_fork(&mut self, proof: &ForkProof) -> ForkTaken;

    /// What changed since this was last asked, in order.
    fn events(&mut self) -> Vec<Event>;

    /// The walk of `chain`'s listed prefix, if one has begun.
    fn walk(&self, chain: ChainId) -> Option<Walk>;

    /// Records heads checked by the walk: `hashes` are those of the
    /// numbers from `lowest` up, and `next` the `prev` of the lowest.
    /// [`Storage::admit`] compares a listed change with them. False if
    /// the storage refuses to keep more (its ceiling on what walks hold):
    /// the walk is then gone, as after [`Storage::walk_end`].
    fn walk_extend(
        &mut self,
        chain: ChainId,
        lowest: u64,
        next: ChangeHash,
        hashes: &[ChangeHash],
    ) -> bool;

    /// Removes the walk of `chain` (the pull reached its pin).
    fn walk_end(&mut self, chain: ChainId);
}
