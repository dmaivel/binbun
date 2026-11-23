//! The sync lane's messages ([`Sync`], sync §3.2), their bounds, and the
//! validity of a reply against the request it answers.
//!
//! Every field is bounded: lists and byte strings by `binbun-bounded`'s
//! types, so [`Sync::decode`] allocates no more than they declare.
//! Heads, proofs and envelopes travel as bounded bytes in their
//! canonical layouts, parsed by fixed offsets (`SignedHead::parse`,
//! `ForkProof::parse`, [`crate::Envelope::parse`]); postcard carries the
//! enum, its integers and its 16- and 32-byte arrays.

use binbun_bounded::{self as bounded, Bounded, Bounds, Bytes};
use binbun_session::journal::{
    ChainId, ChangeHash, ChangeId, FIRST_HEAD, HEAD, MAX_PROOF, MAX_SIGNED_HEAD, MAX_WHY,
    ProjectId, SIG, Tip,
};
use serde::{Deserialize, Serialize};

use crate::envelope::{ENVELOPE_LEAST, MAX_ENVELOPE};

/// The most bytes of a sync frame, checked before its body is read.
pub const FRAME: usize = 2 << 20;

/// The most bytes of a sync frame in Bootstrap (§3.5).
pub const BOOTSTRAP_FRAME: usize = 1 << 20;

/// The most bytes of a page of changes or records with its framing, so a
/// page always fits one frame and one envelope always fits a page.
pub const PAGE_BYTES: usize = 3 << 19;

/// The most bytes of one membership record as signed (§5).
pub const MAX_RECORD: usize = 160 << 10;

/// The most records in a page of them.
pub const RECORDS: usize = 32;

/// The most bytes of a page of records.
pub const RECORDS_BYTES: usize = 1 << 20;

/// The most tips in a [`Sync::TipsPage`].
pub const TIPS_PAGE: usize = 512;

/// The most tips in an unsolicited [`Sync::Tips`].
pub const TIPS: usize = 64;

/// The most changes in a [`Sync::Changes`] page, and the most a
/// [`Sync::Want`] may ask for.
pub const CHANGES: usize = 256;

/// The most changes in a [`Sync::Fresh`].
pub const FRESH: usize = 64;

/// The most numbers a [`Sync::Probe`] asks for.
pub const PROBE: usize = 16;

/// The most heads a [`Sync::HeadsAsk`] asks for in one run.
pub const RUN: usize = 4096;

/// The most bytes of a reason a change was refused.
pub const WHY: usize = MAX_WHY;

/// The most changes in one [`Sync::Refused`].
pub const REFUSED: usize = 64;

/// A 32-byte hash of a record, a genesis or a digest.
pub type Hash = [u8; 32];

/// A membership chain's head: the number of its last record and that
/// record's hash.
pub type Mark = (u64, Hash);

/// The digest of a set of tips, ascending by chain: BLAKE3 derive-key
/// `"binbun/v1/tips"` over each tip's 80 bytes ([`Tip::bytes`]).
#[derive(Debug)]
pub struct Digest {
    hasher: blake3::Hasher,
    count: u32,
}

impl Default for Digest {
    fn default() -> Self {
        Self {
            hasher: blake3::Hasher::new_derive_key("binbun/v1/tips"),
            count: 0,
        }
    }
}

impl Digest {
    /// Adds `tip`, which follows every tip added before it.
    pub fn add(&mut self, tip: &Tip) {
        self.hasher.update(&tip.bytes());
        self.count = self.count.saturating_add(1);
    }

    /// The count and digest.
    pub fn finish(&self) -> (u32, Hash) {
        (self.count, *self.hasher.finalize().as_bytes())
    }
}

/// An envelope as carried: at least [`ENVELOPE_LEAST`] bytes.
pub type EnvelopeBytes = Bytes<MAX_ENVELOPE, ENVELOPE_LEAST>;

/// A membership record as signed, opaque here.
pub type RecordBytes = Bytes<MAX_RECORD, 1>;

/// A signed head in its canonical layout.
pub type SignedHeadBytes = Bytes<MAX_SIGNED_HEAD, { HEAD + SIG }>;

/// A head without its signature, in its canonical layout.
pub type HeadBytes = Bytes<FIRST_HEAD, HEAD>;

/// A fork proof in its canonical layout.
pub type ProofBytes = Bytes<MAX_PROOF, { 64 + 2 * (HEAD + SIG) }>;

/// Why a change was refused, cut to [`WHY`] bytes where it is made.
pub type Why = Bytes<WHY>;

/// A message of the sync lane (sync §3.2). Requests carry an `id`, the
/// sender's own counter, which the reply repeats.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sync {
    /// The sender's membership head: at link-up and whenever it changes,
    /// in Bootstrap and Reader. It acknowledges that head.
    MembershipHead {
        /// The head.
        membership: Mark,
    },
    /// The sender is ready (Bootstrap: once). It names no chain, count
    /// or digest.
    Ready {
        /// The sender's share genesis.
        genesis: Hash,
        /// The sender's membership head.
        membership: Mark,
    },
    /// The sender's membership head and a count and digest of its tips
    /// (Reader only; only when every changed tip has been told).
    Summary {
        /// The membership head.
        membership: Mark,
        /// The count and digest of its tips.
        tips: (u32, Hash),
    },
    /// Asks for membership records after the asker's head.
    RecordsAsk {
        /// The request.
        id: u32,
        /// The asker's last record's number.
        after: u64,
        /// Its hash.
        at: Hash,
    },
    /// A page of records: a reply, or (no id) unsolicited, taken only if
    /// it extends the receiver's chain exactly.
    Records {
        /// The request answered, if any.
        id: Option<u32>,
        /// The records, in order.
        records: Bounded<RecordBytes, RECORDS>,
        /// Whether more follow.
        more: bool,
    },
    /// The responder's record at the asked number, which differs.
    RecordsDiverged {
        /// The request.
        id: u32,
        /// The record, as signed.
        record: RecordBytes,
    },
    /// Asks for a page of tips after a chain.
    TipsAsk {
        /// The request.
        id: u32,
        /// The last chain of the previous page (exclusive), or none.
        after: Option<ChainId>,
        /// Only chains of this origin, if given.
        project: Option<ProjectId>,
    },
    /// A page of tips, ascending, after the request's `after`.
    TipsPage {
        /// The request.
        id: u32,
        /// The tips.
        tips: Bounded<Tip, TIPS_PAGE>,
        /// Where the next page starts, if more follow: the last chain the
        /// responder looked at, at or past the last returned (a page is
        /// bounded by the chains looked at, so it may be short or empty).
        next: Option<ChainId>,
    },
    /// Tips that changed: unsolicited; the only acknowledgement.
    Tips {
        /// The tips.
        tips: Bounded<Tip, TIPS>,
    },
    /// Asks for changes of a chain after the asker's tip.
    Want {
        /// The request.
        id: u32,
        /// The chain.
        chain: ChainId,
        /// The asker's tip's number.
        after: u64,
        /// Its hash (zeros at 0).
        at: ChangeHash,
        /// The most changes wanted, 1 to [`CHANGES`].
        most: u16,
    },
    /// A page of changes answering a `Want`.
    Changes {
        /// The request.
        id: u32,
        /// The chain.
        chain: ChainId,
        /// The envelopes, numbered from `after + 1`.
        changes: Bounded<EnvelopeBytes, CHANGES>,
        /// Whether more follow.
        more: bool,
    },
    /// The responder's head at `after` is not `at`.
    Diverged {
        /// The request.
        id: u32,
        /// The chain.
        chain: ChainId,
    },
    /// Changes just applied, unsolicited.
    Fresh {
        /// The envelopes.
        changes: Bounded<EnvelopeBytes, FRESH>,
    },
    /// Asks for signed heads at numbers of a chain.
    Probe {
        /// The request.
        id: u32,
        /// The chain.
        chain: ChainId,
        /// The numbers, ascending and distinct.
        seqs: Bounded<u64, PROBE>,
    },
    /// The signed heads held of the numbers asked, in order.
    Heads {
        /// The request.
        id: u32,
        /// The chain.
        chain: ChainId,
        /// The heads.
        heads: Bounded<SignedHeadBytes, PROBE>,
    },
    /// Asks for a run of heads ending at `upto`, for a prefix the
    /// share's first record lists (§3.3).
    HeadsAsk {
        /// The request.
        id: u32,
        /// The chain.
        chain: ChainId,
        /// The last number of the run.
        upto: u64,
        /// The most heads, 1 to [`RUN`].
        most: u16,
    },
    /// Heads without signatures, numbered `upto − n + 1` to `upto`; empty
    /// if the responder does not hold them.
    HeadsRun {
        /// The request.
        id: u32,
        /// The chain.
        chain: ChainId,
        /// The heads, ascending.
        heads: Bounded<HeadBytes, RUN>,
    },
    /// Asks for a chain's fork proof.
    ForkAsk {
        /// The request.
        id: u32,
        /// The chain.
        chain: ChainId,
    },
    /// A chain's fork proof, or none: a reply, or (no id, a proof)
    /// unsolicited.
    Fork {
        /// The request answered, if any.
        id: Option<u32>,
        /// The chain.
        chain: ChainId,
        /// The proof.
        proof: Option<ProofBytes>,
    },
    /// Changes of the receiver's that the sender refused, unsolicited.
    Refused {
        /// The changes and why.
        changes: Bounded<(ChangeId, Why), REFUSED>,
    },
}

impl Bounds for Sync {}

impl Sync {
    /// The message `bytes` hold, decoded within its bounds.
    ///
    /// # Errors
    ///
    /// They do not read as one, or bytes are left over.
    pub fn decode(bytes: &[u8]) -> Result<Self, bounded::Error> {
        bounded::decode(bytes)
    }

    /// Its encoding, of at most [`FRAME`] bytes.
    ///
    /// # Errors
    ///
    /// It is larger than a frame.
    pub fn encode(&self) -> Result<Vec<u8>, bounded::Error> {
        bounded::encode(self, FRAME)
    }

    /// The request id it carries, if it is a request.
    pub fn request(&self) -> Option<u32> {
        match self {
            Self::RecordsAsk { id, .. }
            | Self::TipsAsk { id, .. }
            | Self::Want { id, .. }
            | Self::Probe { id, .. }
            | Self::HeadsAsk { id, .. }
            | Self::ForkAsk { id, .. } => Some(*id),
            Self::MembershipHead { .. }
            | Self::Ready { .. }
            | Self::Summary { .. }
            | Self::Records { .. }
            | Self::RecordsDiverged { .. }
            | Self::TipsPage { .. }
            | Self::Tips { .. }
            | Self::Changes { .. }
            | Self::Diverged { .. }
            | Self::Fresh { .. }
            | Self::Heads { .. }
            | Self::HeadsRun { .. }
            | Self::Fork { .. }
            | Self::Refused { .. } => None,
        }
    }

    /// The id of the request it answers, if it is a reply.
    pub fn reply(&self) -> Option<u32> {
        match self {
            Self::RecordsDiverged { id, .. }
            | Self::TipsPage { id, .. }
            | Self::Changes { id, .. }
            | Self::Diverged { id, .. }
            | Self::Heads { id, .. }
            | Self::HeadsRun { id, .. } => Some(*id),
            Self::Records { id, .. } | Self::Fork { id, .. } => *id,
            Self::MembershipHead { .. }
            | Self::Ready { .. }
            | Self::Summary { .. }
            | Self::RecordsAsk { .. }
            | Self::TipsAsk { .. }
            | Self::Tips { .. }
            | Self::Want { .. }
            | Self::Fresh { .. }
            | Self::Probe { .. }
            | Self::HeadsAsk { .. }
            | Self::ForkAsk { .. }
            | Self::Refused { .. } => None,
        }
    }

    /// Whether it may pass in Bootstrap (§3.6): the membership head,
    /// records and `Ready`, nothing that names a chain, count or digest.
    pub fn in_bootstrap(&self) -> bool {
        match self {
            Self::MembershipHead { .. }
            | Self::RecordsAsk { .. }
            | Self::Records { .. }
            | Self::RecordsDiverged { .. }
            | Self::Ready { .. } => true,
            Self::Summary { .. }
            | Self::TipsAsk { .. }
            | Self::TipsPage { .. }
            | Self::Tips { .. }
            | Self::Want { .. }
            | Self::Changes { .. }
            | Self::Diverged { .. }
            | Self::Fresh { .. }
            | Self::Probe { .. }
            | Self::Heads { .. }
            | Self::HeadsAsk { .. }
            | Self::HeadsRun { .. }
            | Self::ForkAsk { .. }
            | Self::Fork { .. }
            | Self::Refused { .. } => false,
        }
    }

    /// Its name, for causes and counts.
    pub fn name(&self) -> &'static str {
        match self {
            Self::MembershipHead { .. } => "MembershipHead",
            Self::Ready { .. } => "Ready",
            Self::Summary { .. } => "Summary",
            Self::RecordsAsk { .. } => "RecordsAsk",
            Self::Records { .. } => "Records",
            Self::RecordsDiverged { .. } => "RecordsDiverged",
            Self::TipsAsk { .. } => "TipsAsk",
            Self::TipsPage { .. } => "TipsPage",
            Self::Tips { .. } => "Tips",
            Self::Want { .. } => "Want",
            Self::Changes { .. } => "Changes",
            Self::Diverged { .. } => "Diverged",
            Self::Fresh { .. } => "Fresh",
            Self::Probe { .. } => "Probe",
            Self::Heads { .. } => "Heads",
            Self::HeadsAsk { .. } => "HeadsAsk",
            Self::HeadsRun { .. } => "HeadsRun",
            Self::ForkAsk { .. } => "ForkAsk",
            Self::Fork { .. } => "Fork",
            Self::Refused { .. } => "Refused",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail loudly")]

    use super::*;

    #[test]
    fn every_field_of_a_message_is_bounded() {
        bounded::walk::<Sync>().unwrap();
    }

    #[test]
    fn the_digest_is_of_each_tips_80_bytes_in_order_under_its_domain() {
        let tip = |n: u8| Tip {
            chain: ChainId([n; 16]),
            project: ProjectId([2; 16]),
            seq: u64::from(n),
            hash: ChangeHash([3; 32]),
            fork: 0,
        };
        let mut digest = Digest::default();
        digest.add(&tip(1));
        digest.add(&tip(2));
        let mut expected = blake3::Hasher::new_derive_key("binbun/v1/tips");
        expected.update(&tip(1).bytes());
        expected.update(&tip(2).bytes());
        assert_eq!(digest.finish(), (2, *expected.finalize().as_bytes()));
        let mut reversed = Digest::default();
        reversed.add(&tip(2));
        reversed.add(&tip(1));
        assert_ne!(reversed.finish(), digest.finish());
    }

    #[test]
    fn a_page_of_the_largest_changes_fits_a_frame() {
        let one = EnvelopeBytes::try_from(vec![0; MAX_ENVELOPE]).unwrap();
        let message = Sync::Changes {
            id: u32::MAX,
            chain: ChainId([0; 16]),
            changes: Bounded::try_from(vec![one]).unwrap(),
            more: true,
        };
        assert!(message.encode().unwrap().len() <= PAGE_BYTES);
    }

    #[test]
    fn a_frame_past_its_limit_does_not_encode() {
        let one = EnvelopeBytes::try_from(vec![0; MAX_ENVELOPE]).unwrap();
        let message = Sync::Fresh {
            changes: Bounded::try_from(vec![one.clone(), one]).unwrap(),
        };
        assert!(message.encode().is_err());
    }
}
