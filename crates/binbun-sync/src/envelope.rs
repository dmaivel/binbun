//! The envelope of a change as it travels (sync §2.2): its public head
//! and signature beside the sealed body. This is the only parser and
//! writer of the layout; sealing and opening, which need the epoch's
//! keys, are the caller's and are built on it.
//!
//! ```text
//! Envelope = project:16 ‖ head ‖ author_sig:64 ‖ epoch:u32 ‖ nonce:24 ‖ ct ‖ sealer:32 ‖ seal_sig:64
//! length   = 308 + body (372 + body for a first change)
//! ```
//!
//! [`Envelope::parse`] reads fixed offsets, checks the exact length and
//! allocates nothing. It verifies nothing: a head read from it is
//! unauthenticated until the journal has checked its signature.

use binbun_session::journal::{
    ChainId, ChangeHash, FIRST_HEAD, HEAD, MAX_BODY, ProjectId, SIG as SIGNATURE,
};

/// The bytes the AEAD adds to a body.
pub const TAG: usize = 16;

/// The bytes of an envelope around its head and body.
const AROUND: usize = 16 + SIGNATURE + 4 + 24 + TAG + 32 + SIGNATURE;

/// The fewest bytes of an envelope: a change after the first, empty body.
pub const ENVELOPE_LEAST: usize = AROUND + HEAD;

/// The most bytes of an envelope: a first change of the largest body.
pub const MAX_ENVELOPE: usize = AROUND + FIRST_HEAD + MAX_BODY;

/// An envelope's parts, borrowed from its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope<'a> {
    bytes: &'a [u8],
    /// The head's bytes: [`HEAD`] or [`FIRST_HEAD`].
    head: usize,
}

/// The parts an envelope is written from.
#[derive(Clone, Copy, Debug)]
pub struct Parts<'a> {
    /// The share's id.
    pub project: ProjectId,
    /// The head and its author's signature, in their canonical layout.
    pub signed_head: &'a [u8],
    /// The epoch sealed in.
    pub epoch: u32,
    /// The nonce.
    pub nonce: &'a [u8; 24],
    /// The sealed body, its tag included.
    pub ciphertext: &'a [u8],
    /// Whoever sealed it.
    pub sealer: &'a [u8; 32],
    /// The sealer's signature.
    pub seal_sig: &'a [u8; 64],
}

/// `N` bytes of `bytes` at `at`.
fn array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0; N];
    if let Some(from) = bytes.get(at..at.saturating_add(N)) {
        out.copy_from_slice(from);
    }
    out
}

impl<'a> Envelope<'a> {
    /// The envelope `bytes` hold, if they are exactly one: a number of at
    /// least 1, the head its number calls for, and a body of at most
    /// [`MAX_BODY`].
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let seq = u64::from_be_bytes(array(bytes.get(..40)?, 32));
        let head = match seq {
            0 => return None,
            1 => FIRST_HEAD,
            _ => HEAD,
        };
        let fixed = AROUND - TAG + head;
        let ciphertext = bytes.len().checked_sub(fixed)?;
        (TAG..=MAX_BODY + TAG)
            .contains(&ciphertext)
            .then_some(Self { bytes, head })
    }

    /// The envelope written from `parts`, if they make one.
    pub fn write(parts: &Parts<'_>) -> Option<Vec<u8>> {
        let length = 16usize
            .checked_add(parts.signed_head.len())?
            .checked_add(4 + 24 + 32 + SIGNATURE)?
            .checked_add(parts.ciphertext.len())?;
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(&parts.project.0);
        bytes.extend_from_slice(parts.signed_head);
        bytes.extend_from_slice(&parts.epoch.to_be_bytes());
        bytes.extend_from_slice(parts.nonce);
        bytes.extend_from_slice(parts.ciphertext);
        bytes.extend_from_slice(parts.sealer);
        bytes.extend_from_slice(parts.seal_sig);
        let whole =
            Envelope::parse(&bytes).is_some_and(|parsed| parsed.signed_head() == parts.signed_head);
        whole.then_some(bytes)
    }

    /// All its bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The share it was sealed for.
    pub fn project(&self) -> ProjectId {
        ProjectId(array(self.bytes, 0))
    }

    /// The head's canonical bytes.
    pub fn head(&self) -> &'a [u8] {
        self.bytes.get(16..16 + self.head).unwrap_or_default()
    }

    /// The head and its author's signature, in their canonical layout.
    pub fn signed_head(&self) -> &'a [u8] {
        self.bytes
            .get(16..16 + self.head + SIGNATURE)
            .unwrap_or_default()
    }

    /// The head's chain.
    pub fn chain(&self) -> ChainId {
        ChainId(array(self.bytes, 16))
    }

    /// The head's number.
    pub fn seq(&self) -> u64 {
        u64::from_be_bytes(array(self.bytes, 32))
    }

    /// The head's `prev`: the hash of the change before (zeros at 1).
    pub fn prev(&self) -> ChangeHash {
        ChangeHash(array(self.bytes, 40))
    }

    /// Where the seal's part starts.
    fn sealed_at(&self) -> usize {
        16 + self.head + SIGNATURE
    }

    /// The epoch it was sealed in.
    pub fn epoch(&self) -> u32 {
        u32::from_be_bytes(array(self.bytes, self.sealed_at()))
    }

    /// The nonce.
    pub fn nonce(&self) -> [u8; 24] {
        array(self.bytes, self.sealed_at() + 4)
    }

    /// The sealed body, its tag included.
    pub fn ciphertext(&self) -> &'a [u8] {
        let end = self.bytes.len().saturating_sub(32 + SIGNATURE);
        self.bytes
            .get(self.sealed_at() + 28..end)
            .unwrap_or_default()
    }

    /// Whoever sealed it (named only once the seal has been verified).
    pub fn sealer(&self) -> [u8; 32] {
        array(self.bytes, self.bytes.len().saturating_sub(32 + SIGNATURE))
    }

    /// The sealer's signature.
    pub fn seal_sig(&self) -> [u8; 64] {
        array(self.bytes, self.bytes.len().saturating_sub(SIGNATURE))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail loudly")]

    use super::*;

    /// A signed head's bytes of number `seq`, its other fields `fill`.
    fn signed_head(seq: u64, fill: u8) -> Vec<u8> {
        let head = if seq == 1 { FIRST_HEAD } else { HEAD };
        let mut bytes = vec![fill; head + SIGNATURE];
        bytes[16..24].copy_from_slice(&seq.to_be_bytes());
        bytes
    }

    fn envelope(seq: u64, body: usize) -> Vec<u8> {
        let head = signed_head(seq, 7);
        Envelope::write(&Parts {
            project: ProjectId([1; 16]),
            signed_head: &head,
            epoch: 0x0a0b_0c0d,
            nonce: &[2; 24],
            ciphertext: &vec![3; body + TAG],
            sealer: &[4; 32],
            seal_sig: &[5; 64],
        })
        .unwrap()
    }

    #[test]
    fn the_lengths_are_the_designs() {
        assert_eq!(envelope(2, 0).len(), 308);
        assert_eq!(envelope(1, 0).len(), 372);
        assert_eq!(envelope(9, 100).len(), 408);
        assert_eq!(envelope(2, 0).len(), ENVELOPE_LEAST);
        assert_eq!(envelope(1, MAX_BODY).len(), MAX_ENVELOPE);
    }

    #[test]
    fn every_part_reads_back_from_its_offset() {
        let bytes = envelope(1, 10);
        let parsed = Envelope::parse(&bytes).unwrap();
        assert_eq!(parsed.project(), ProjectId([1; 16]));
        assert_eq!(parsed.seq(), 1);
        assert_eq!(parsed.chain(), ChainId([7; 16]));
        assert_eq!(parsed.prev(), ChangeHash([7; 32]));
        assert_eq!(parsed.signed_head(), signed_head(1, 7));
        assert_eq!(parsed.head().len(), FIRST_HEAD);
        assert_eq!(parsed.epoch(), 0x0a0b_0c0d);
        assert_eq!(parsed.nonce(), [2; 24]);
        assert_eq!(parsed.ciphertext(), [3; 10 + TAG]);
        assert_eq!(parsed.sealer(), [4; 32]);
        assert_eq!(parsed.seal_sig(), [5; 64]);
    }

    #[test]
    fn a_length_its_number_does_not_call_for_is_refused() {
        // Number 0 is no change.
        let mut zero = envelope(2, 0);
        zero[32..40].copy_from_slice(&0u64.to_be_bytes());
        assert!(Envelope::parse(&zero).is_none());
        // A first change's bytes read as a later one's (and the reverse)
        // leave a ciphertext too short or the head misplaced: the lengths
        // of each, a byte short, do not parse.
        for seq in [1, 2, u64::MAX] {
            let bytes = envelope(seq, 0);
            assert!(Envelope::parse(&bytes).is_some());
            assert!(Envelope::parse(&bytes[..bytes.len() - 1]).is_none());
        }
        let mut first = envelope(2, 0);
        first[32..40].copy_from_slice(&1u64.to_be_bytes());
        assert!(Envelope::parse(&first).is_none());
        // A body past the most.
        let mut big = envelope(2, MAX_BODY);
        assert!(Envelope::parse(&big).is_some());
        big.push(0);
        assert!(Envelope::parse(&big).is_none());
        assert!(Envelope::parse(&[]).is_none());
    }
}
