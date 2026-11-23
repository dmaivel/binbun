//! A change as signed, kept and sent (sync §2.1): a small public **head**
//! its author signs (its chain, number, predecessor's hash and the
//! commitment to its body) and a **body** (what it does), which only the
//! commitment ties to the head. A change's identity is the hash of its
//! head ([`ChangeHash`]): the same however it is carried.
//!
//! Heads, signed heads and fork proofs have canonical byte layouts
//! (integers big-endian), read by fixed offsets with the exact length
//! checked and nothing allocated ([`Head::parse`], [`SignedHead::parse`],
//! [`ForkProof::parse`]). A body is postcard, decoded within declared
//! bounds ([`Body::decode`]).
//!
//! ```text
//! Head        chain:16 ‖ seq:u64 ‖ prev:32 ‖ body:32                    88 bytes
//!             seq = 1 only: ‖ author:32 ‖ project:16 ‖ salt:16        152 bytes; prev zeros
//! SignedHead  head ‖ sig:64                                     152 or 216 bytes
//! change hash BLAKE3 derive-key("binbun/v1/change", head)
//! commitment  BLAKE3 derive-key("binbun/v1/body", body)
//! signature   Ed25519(author, "binbun/v1/head" ‖ head), checked strictly
//! ForkProof   author:32 ‖ project:16 ‖ salt:16 ‖ a ‖ b                 ≤ 496 bytes
//! a change    signed head ‖ LEB128 length ‖ body (the log's record)
//! ```

use std::fmt;
use std::ops::Deref;

use binbun_bounded::Bounds;
use ed25519_dalek::{Signature, Signer as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{
    ChainId, ChainOrigin, ChangeId, EngineVersion, Hlc, Op, Origin, ProjectId, PublicKey, Signer,
    hex, wire,
};

/// The most bytes of a change's body.
pub const MAX_BODY: usize = 1 << 20;

/// The most bytes of a chain's start's body (its binding and nothing
/// else).
pub const MAX_START: usize = 512;

/// The most ops of one change.
pub const MAX_OPS: usize = 65_535;

/// The most parts of one group.
pub const MAX_PARTS: u16 = 16;

/// The bytes of a head past a chain's first change.
pub const HEAD: usize = 88;

/// The bytes of a chain's first head.
pub const FIRST_HEAD: usize = 152;

/// The bytes of a signature.
pub const SIG: usize = 64;

/// The most bytes of a signed head.
pub const MAX_SIGNED_HEAD: usize = FIRST_HEAD + SIG;

/// The bytes of a chain's origin in a proof.
const ORIGIN: usize = 64;

/// The most bytes of a fork proof.
pub const MAX_PROOF: usize = ORIGIN + 2 * MAX_SIGNED_HEAD;

/// The bytes of a tip as its digest takes it.
pub const TIP: usize = 80;

/// The domain of a change's hash.
const CHANGE: &str = "binbun/v1/change";

/// The domain of a body's commitment.
const BODY: &str = "binbun/v1/body";

/// What an author's signature of a head is of, before the head.
const SIGNED: &[u8] = b"binbun/v1/head";

/// A change's identity: BLAKE3 of its head, under its own domain.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChangeHash(pub [u8; 32]);

impl ChangeHash {
    /// No change's: the `prev` of a chain's first.
    pub const ZERO: Self = Self([0; 32]);
}

impl fmt::Display for ChangeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex(&self.0, f)
    }
}

impl fmt::Debug for ChangeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChangeHash({self})")
    }
}

/// Why bytes are no head, signed head, proof or change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed(pub &'static str);

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Malformed {}

/// Canonical bytes of at most `N`, on the stack.
#[derive(Clone, Copy)]
pub struct Canonical<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Canonical<N> {
    /// None yet.
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    /// `bytes` after those so far (as many as fit).
    fn put(&mut self, bytes: &[u8]) {
        let end = (self.len + bytes.len()).min(N);
        if let Some(to) = self.bytes.get_mut(self.len..end) {
            to.copy_from_slice(bytes.get(..end - self.len).unwrap_or_default());
        }
        self.len = end;
    }
}

impl<const N: usize> Deref for Canonical<N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

impl<const N: usize> fmt::Debug for Canonical<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Canonical({})", self.len)
    }
}

/// `N` bytes of `bytes` from `at`.
fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], Malformed> {
    bytes
        .get(at..at + N)
        .and_then(|slice| <[u8; N]>::try_from(slice).ok())
        .ok_or(Malformed("too short"))
}

/// The number of the head at the start of `bytes` (after its chain).
fn seq_at(bytes: &[u8]) -> Result<u64, Malformed> {
    Ok(u64::from_be_bytes(array(bytes, 16)?))
}

/// The bytes of a head of number `seq`.
const fn head_len(seq: u64) -> usize {
    if seq == 1 { FIRST_HEAD } else { HEAD }
}

/// What an author signs, sealed into the journal: a change's position,
/// its link to the one before, and its body's commitment; the first of a
/// chain also what makes the chain's id ([`ChainOrigin`]), so it proves
/// whose the chain is to anyone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Head {
    /// Its chain.
    pub chain: ChainId,
    /// Its number there, from 1.
    pub seq: u64,
    /// The hash of the change before it ([`ChangeHash::ZERO`] for the
    /// first).
    pub prev: ChangeHash,
    /// Its body's commitment ([`Body::commitment`]).
    pub body: [u8; 32],
    /// What makes the chain's id: on the first change only.
    pub origin: Option<ChainOrigin>,
}

impl Head {
    /// Its id: chain and number.
    pub fn id(&self) -> ChangeId {
        ChangeId {
            chain: self.chain,
            seq: self.seq,
        }
    }

    /// Whether its fields agree: a number from 1; an origin making its
    /// chain and no predecessor exactly at 1.
    pub fn well_formed(&self) -> bool {
        match (self.seq, &self.origin) {
            (1, Some(origin)) => self.prev == ChangeHash::ZERO && origin.chain() == self.chain,
            (0, _) | (1, None) | (_, Some(_)) => false,
            (_, None) => true,
        }
    }

    /// Its author, if it is a chain's first (whose origin names it).
    pub fn author(&self) -> Option<PublicKey> {
        self.origin.map(|origin| origin.author)
    }

    /// Its canonical bytes.
    pub fn bytes(&self) -> Canonical<FIRST_HEAD> {
        let mut out = Canonical::new();
        out.put(&self.chain.0);
        out.put(&self.seq.to_be_bytes());
        out.put(&self.prev.0);
        out.put(&self.body);
        if let Some(origin) = &self.origin {
            out.put(&origin.author.0);
            out.put(&origin.project.0);
            out.put(&origin.salt);
        }
        out
    }

    /// The head `bytes` are, exactly.
    ///
    /// # Errors
    ///
    /// They are not one head's bytes, or its fields disagree.
    pub fn parse(bytes: &[u8]) -> Result<Self, Malformed> {
        let seq = seq_at(bytes)?;
        if bytes.len() != head_len(seq) {
            return Err(Malformed("a head of another length"));
        }
        let origin = (seq == 1)
            .then(|| -> Result<ChainOrigin, Malformed> {
                Ok(ChainOrigin {
                    author: PublicKey(array(bytes, HEAD)?),
                    project: ProjectId(array(bytes, HEAD + 32)?),
                    salt: array(bytes, HEAD + 48)?,
                })
            })
            .transpose()?;
        let head = Self {
            chain: ChainId(array(bytes, 0)?),
            seq,
            prev: ChangeHash(array(bytes, 24)?),
            body: array(bytes, 56)?,
            origin,
        };
        if head.well_formed() {
            Ok(head)
        } else {
            Err(Malformed("a head whose origin does not make its chain"))
        }
    }

    /// Its hash: the change's identity.
    pub fn hash(&self) -> ChangeHash {
        let mut hasher = blake3::Hasher::new_derive_key(CHANGE);
        hasher.update(&self.bytes());
        ChangeHash(*hasher.finalize().as_bytes())
    }

    /// What its author signs.
    fn signed(&self) -> Canonical<{ SIGNED.len() + FIRST_HEAD }> {
        let mut out = Canonical::new();
        out.put(SIGNED);
        out.put(&self.bytes());
        out
    }
}

/// A head and its author's signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedHead {
    /// The head.
    pub head: Head,
    /// Its author's signature of it.
    pub sig: Signature,
}

impl SignedHead {
    /// `head`, signed by `signer`.
    pub fn sign(head: Head, signer: &Signer) -> Self {
        Self {
            sig: signer.key.sign(&head.signed()),
            head,
        }
    }

    /// Whether `author` signed it.
    pub fn verify(&self, author: PublicKey) -> bool {
        VerifyingKey::from_bytes(&author.0)
            .is_ok_and(|key| key.verify_strict(&self.head.signed(), &self.sig).is_ok())
    }

    /// Its head's hash.
    pub fn hash(&self) -> ChangeHash {
        self.head.hash()
    }

    /// Its id.
    pub fn id(&self) -> ChangeId {
        self.head.id()
    }

    /// Its canonical bytes.
    pub fn bytes(&self) -> Canonical<MAX_SIGNED_HEAD> {
        let mut out = Canonical::new();
        out.put(&self.head.bytes());
        out.put(&self.sig.to_bytes());
        out
    }

    /// The signed head `bytes` are, exactly.
    ///
    /// # Errors
    ///
    /// They are not one signed head's bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, Malformed> {
        let (head, rest) = Self::take(bytes)?;
        if rest.is_empty() {
            Ok(head)
        } else {
            Err(Malformed("bytes past a signed head"))
        }
    }

    /// The signed head at the start of `bytes`, and what follows it.
    ///
    /// # Errors
    ///
    /// They do not start with one.
    pub fn take(bytes: &[u8]) -> Result<(Self, &[u8]), Malformed> {
        let length = head_len(seq_at(bytes)?);
        let head = Head::parse(bytes.get(..length).ok_or(Malformed("too short"))?)?;
        let sig = Signature::from_bytes(&array(bytes, length)?);
        let rest = bytes.get(length + SIG..).ok_or(Malformed("too short"))?;
        Ok((Self { head, sig }, rest))
    }
}

/// What a chain's changes are of: the share it was begun in, if any,
/// and the binary or set log. A chain's first body says it, signed and
/// fixed for every change after it by the hash chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Bound {
    /// The share the chain was begun in, and the grant it is written
    /// under, if it was begun in one.
    pub share: Option<Under>,
    /// Its binary, or the set log.
    pub of: Of,
}

/// The share a chain is of, and the membership record whose role it is
/// written under (sync §4.3): that record's role is the chain's at every
/// number, whatever records come later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Under {
    /// The share's genesis (the hash of its first membership record).
    pub genesis: [u8; 32],
    /// The number of the membership record that set the author's entry,
    /// as the chain was begun: its grant.
    pub grant: u64,
}

/// The log a chain is of.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Of {
    /// A binary: the whole file's SHA-256, and the slice of a universal
    /// file resolved (its architecture), if it is one.
    Binary {
        /// The whole file's SHA-256.
        sha256: [u8; 32],
        /// The slice's architecture, of a universal file.
        #[serde(deserialize_with = "wire::opt_text")]
        slice: Option<String>,
    },
    /// The set log of a project of several binaries.
    Set,
}

/// One of the consecutive changes of a chain a group too large for one
/// change was split into: one undo step, one history entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Group {
    /// The number of its first part.
    pub first: u64,
    /// How many parts it was split into (2 to [`MAX_PARTS`]).
    pub count: u16,
}

impl Group {
    /// Whether change `seq` can be one of its parts: 2 to 16 parts, from
    /// `first`, `seq` among them.
    pub fn holds(self, seq: u64) -> bool {
        (2..=MAX_PARTS).contains(&self.count)
            && self.first >= 2
            && seq
                .checked_sub(self.first)
                .is_some_and(|past| past < u64::from(self.count))
    }
}

/// What a change does, as its author sealed it: postcard, at most
/// [`MAX_BODY`] bytes, decoded within declared bounds.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Body {
    /// What the chain is of: on its first change only.
    pub bound: Option<Bound>,
    /// Its time.
    pub hlc: Hlc,
    /// The latest membership record its author had seen: a hint, which
    /// no rule reads for rights.
    pub membership: u64,
    /// The binbun that made it.
    pub engine: EngineVersion,
    /// Who or what made it.
    pub origin: Origin,
    /// What it did, for people (`Rename function`, `Undo: …`).
    #[serde(deserialize_with = "wire::text")]
    pub label: String,
    /// The change it undoes or makes again ([`Origin::Undo`],
    /// [`Origin::Redo`]).
    pub undoes: Option<ChangeId>,
    /// The group it is a part of, if one too large for one change.
    pub group: Option<Group>,
    /// Its ops.
    #[serde(deserialize_with = "wire::ops")]
    pub ops: Vec<Op>,
    /// 16 random bytes, made once for this body: its commitment gives
    /// nothing to test guesses of its contents against.
    pub blind: [u8; 16],
}

impl Bounds for Body {}

impl Body {
    /// The commitment to body bytes `bytes`.
    pub fn commitment(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(BODY);
        hasher.update(bytes);
        *hasher.finalize().as_bytes()
    }

    /// The body `bytes` hold, all of them, within its bounds.
    ///
    /// # Errors
    ///
    /// They are more than [`MAX_BODY`], or do not read as a body within
    /// its bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_BODY {
            return Err(format!("a body of more than {MAX_BODY} bytes"));
        }
        binbun_bounded::decode(bytes).map_err(|error| format!("its body {error}"))
    }

    /// Its bytes.
    ///
    /// # Errors
    ///
    /// They would be more than [`MAX_BODY`].
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        binbun_bounded::encode(self, MAX_BODY)
            .map_err(|_| format!("a change of more than {MAX_BODY} bytes"))
    }

    /// Whether it is a chain's start: its binding and nothing else.
    pub fn is_start(&self) -> bool {
        self.bound.is_some()
            && self.ops.is_empty()
            && self.group.is_none()
            && self.undoes.is_none()
            && self.label.is_empty()
    }
}

/// A change as signed: its signed head and its body's bytes, exactly as
/// sealed. The journal's unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedChange {
    /// Its signed head.
    pub head: SignedHead,
    /// Its body, as committed to (at most [`MAX_BODY`] bytes).
    pub body: Vec<u8>,
}

impl SignedChange {
    /// Its id.
    pub fn id(&self) -> ChangeId {
        self.head.id()
    }

    /// Its hash.
    pub fn hash(&self) -> ChangeHash {
        self.head.hash()
    }

    /// Whether its body is the one its head commits to.
    pub fn opens(&self) -> bool {
        Body::commitment(&self.body) == self.head.head.body
    }

    /// Its encoding: signed head, LEB128 length, body (the log's record).
    pub fn encode(&self) -> Vec<u8> {
        let head = self.head.bytes();
        let mut out = Vec::with_capacity(head.len() + 10 + self.body.len());
        out.extend_from_slice(&head);
        leb128(&mut out, self.body.len());
        out.extend_from_slice(&self.body);
        out
    }

    /// The change `bytes` encode, exactly.
    ///
    /// # Errors
    ///
    /// They are not one change's encoding.
    pub fn parse(bytes: &[u8]) -> Result<Self, Malformed> {
        let (change, rest) = Self::take(bytes)?;
        if rest.is_empty() {
            Ok(change)
        } else {
            Err(Malformed("bytes past a change"))
        }
    }

    /// The change at the start of `bytes`, and what follows it; its body's
    /// length is checked against [`MAX_BODY`] before its bytes are copied.
    ///
    /// # Errors
    ///
    /// They do not start with one.
    pub fn take(bytes: &[u8]) -> Result<(Self, &[u8]), Malformed> {
        let (head, rest) = SignedHead::take(bytes)?;
        let (length, rest) = read_leb128(rest).ok_or(Malformed("no body's length"))?;
        let length = usize::try_from(length)
            .ok()
            .filter(|&length| length <= MAX_BODY)
            .ok_or(Malformed("a body of more than 1 MiB"))?;
        let (body, rest) = rest
            .split_at_checked(length)
            .ok_or(Malformed("a body cut short"))?;
        Ok((
            Self {
                head,
                body: body.to_vec(),
            },
            rest,
        ))
    }
}

/// Two heads of one chain signed by its author that cannot both be on it:
/// at one number with different hashes, or one after the other with the
/// later not naming the earlier. Anyone can check it, without a key or the
/// bodies; only the chain's author can cause one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkProof {
    /// What makes the chain's id, its author first.
    pub origin: ChainOrigin,
    /// The earlier head (at one number: the lower hash).
    pub a: SignedHead,
    /// The other.
    pub b: SignedHead,
}

impl ForkProof {
    /// The proof `x` and `y` make of `origin`'s chain, ordered, if they
    /// make one.
    pub fn new(origin: ChainOrigin, x: SignedHead, y: SignedHead) -> Option<Self> {
        let (a, b) = if x.head.seq < y.head.seq || (x.head.seq == y.head.seq && x.hash() < y.hash())
        {
            (x, y)
        } else {
            (y, x)
        };
        let proof = Self { origin, a, b };
        proof.verify().then_some(proof)
    }

    /// Whether it proves a fork: both heads of the chain its origin makes,
    /// signed by its author, in one of the two shapes, ordered.
    pub fn verify(&self) -> bool {
        let chain = self.origin.chain();
        let of_chain = |signed: &SignedHead| {
            signed.head.chain == chain
                && signed.head.well_formed()
                && signed
                    .head
                    .origin
                    .is_none_or(|origin| origin == self.origin)
                && signed.verify(self.origin.author)
        };
        let (a, b) = (&self.a.head, &self.b.head);
        let shape = if a.seq == b.seq {
            self.a.hash() < self.b.hash()
        } else {
            a.seq.checked_add(1) == Some(b.seq) && b.prev != self.a.hash()
        };
        shape && of_chain(&self.a) && of_chain(&self.b)
    }

    /// The chain it is of.
    pub fn chain(&self) -> ChainId {
        self.origin.chain()
    }

    /// Its place: from where the chain freezes.
    pub fn place(&self) -> u64 {
        self.a.head.seq
    }

    /// Its canonical bytes.
    pub fn bytes(&self) -> Canonical<MAX_PROOF> {
        let mut out = Canonical::new();
        out.put(&self.origin.author.0);
        out.put(&self.origin.project.0);
        out.put(&self.origin.salt);
        out.put(&self.a.bytes());
        out.put(&self.b.bytes());
        out
    }

    /// The proof `bytes` are, exactly (not yet verified: [`Self::verify`]).
    ///
    /// # Errors
    ///
    /// They are not one proof's bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, Malformed> {
        let origin = ChainOrigin {
            author: PublicKey(array(bytes, 0)?),
            project: ProjectId(array(bytes, 32)?),
            salt: array(bytes, 48)?,
        };
        let rest = bytes.get(ORIGIN..).ok_or(Malformed("too short"))?;
        let (a, rest) = SignedHead::take(rest)?;
        let b = SignedHead::parse(rest)?;
        Ok(Self { origin, a, b })
    }
}

/// What is kept of a chain frozen by its author's own doing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// A fork: shown to any replica that holds the chain.
    Proof(Box<ForkProof>),
    /// The signed head of a change refused for good (`Never`): local
    /// evidence, told as proof of nothing.
    Refused(Box<SignedHead>),
}

/// A chain as told: how far it is admitted here, below any fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Tip {
    /// The chain.
    pub chain: ChainId,
    /// The log it is of: its origin's.
    pub project: ProjectId,
    /// The number admitted up to (0: none, a fork at its first).
    pub seq: u64,
    /// The hash of the change there ([`ChangeHash::ZERO`] at 0).
    pub hash: ChangeHash,
    /// The place of its fork, if one is proved (else 0).
    pub fork: u64,
}

impl Tip {
    /// The bytes a digest of tips takes of it: `chain ‖ project ‖ seq ‖
    /// hash ‖ fork`.
    pub fn bytes(&self) -> [u8; TIP] {
        let mut out = Canonical::<TIP>::new();
        out.put(&self.chain.0);
        out.put(&self.project.0);
        out.put(&self.seq.to_be_bytes());
        out.put(&self.hash.0);
        out.put(&self.fork.to_be_bytes());
        out.bytes
    }
}

/// Appends `value` as LEB128.
pub(crate) fn leb128(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let byte = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A LEB128 number at the start of `bytes`, and what follows it.
pub(crate) fn read_leb128(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value: u64 = 0;
    for (at, &byte) in bytes.iter().enumerate().take(10) {
        value |= u64::from(byte & 0x7f) << (7 * at);
        if byte & 0x80 == 0 {
            return Some((value, bytes.get(at + 1..)?));
        }
    }
    None
}
