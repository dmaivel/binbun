//! Who may do what in a shared project:
//! the **membership chain**, written by the project's one owner only, so
//! its records have one order without consensus, and checked by every
//! peer alike.
//!
//! - Each record ([`Record`]) is numbered from 1, names its
//!   predecessor's hash and is signed by the owner ([`SignedRecord`]); the
//!   first ([`Op::Create`]) names the owner, whom a joiner knows from the
//!   ticket. The owner may give the project to a member
//!   ([`Op::TransferOwner`]): the new owner signs every record after it,
//!   and the one before becomes an editor. A host can check the chain
//!   without any key: it holds no secret, only keys, roles, cuts,
//!   the prefixes listed, the binary sealed and key wraps. Records carry
//!   no project ids: a chain says in its own first change which share
//!   and binary it is of.
//! - **Genesis** ([`Membership::genesis`]): the BLAKE3 of the first
//!   record's signed bytes names the share. **Who signs** is said by one
//!   function, [`Membership::signer`]: the owner after every transfer.
//! - **History from before the share** ([`Membership::before`]): the
//!   first record lists, for each chain of the owner's project chosen to
//!   go with it ([`MAX_BEFORE`] at most), the number it is taken up to
//!   ([`MAX_THROUGH`] at most) and the hash of the change there. That
//!   listing is the prefix's authorisation, for good.
//! - **Bounds**, the same on every copy: a record of [`MAX_RECORD`]
//!   bytes at most signed, a wrap of exactly [`WRAP`] bytes per reader, a cut
//!   of [`MAX_CUT`] chains, [`MAX_MEMBERS`] members not removed, a
//!   history link of exactly [`HISTORY`] bytes; and by bytes, a record
//!   other than a removal only while the chain with it is at most
//!   [`MAX_CHAIN`] bytes, a removal while it is at most
//!   [`MAX_CHAIN_REMOVING`] ([`Membership::crowded`] past
//!   [`CROWDED`]): removals still fit where other records no longer do.
//! - **The binary** ([`Binary`]): each record that starts an epoch (the
//!   first, a removal) names the binary the project annotates, sealed
//!   under that epoch's key (a member given no key learns nothing of
//!   it); a peer syncs only a session on it.
//! - **Roles** ([`Role`]): the owner, editors and agents edit; viewers
//!   read and talk in threads; a store ([`Role::Store`]) writes nothing
//!   and is given no key: records may name one, and this build links with
//!   none. A change is judged by the most it writes ([`Writes`]), in one
//!   of three verdicts ([`Membership::judge`]).
//! - **Epochs**: the chain starts epoch 0, its key wrapped to the owner;
//!   adding a reader wraps the epoch's key to them; removing a member
//!   starts the next epoch, its key wrapped to every reader left.
//!   The record starting an epoch carries the history link
//!   ([`crypto::seal_history`]): the subkeys of the epoch before, sealed
//!   under the new one's, from which a member given any epoch's key
//!   derives those of every earlier epoch ([`Membership::history`]).
//! - **Grants** (sync §4.3): a record that sets a member's entry with a
//!   role (creation, an addition, a role change, a readmission, a
//!   transfer) is a grant. A chain's start names the grant it is written
//!   under, and that record's role is the chain's at every number, on
//!   every peer, whatever records come later ([`Membership::judge`]): a
//!   change the role may not write is refused for good; the only wait is
//!   a start's, for its grant's record.
//! - **Cuts**: the first record after a chain's grant that leaves its
//!   author able to write less than the grant gave (a removal, a role
//!   lowered) closes the chain: past the last change its cut names, or at
//!   its start if the cut does not name it (the owner never saw it).
//!   Closing is final. A record that raises a role, a transfer and a
//!   readmission carry no cut and close nothing: new rights are used on a
//!   new chain naming the new grant.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use binbun_bounded::{self as bounded, Bounded, Bounds, Bytes, Exact, Map, Text};
use binbun_session::journal::talk::{SuggestionOp, SuggestionState};
use binbun_session::journal::{
    Body, ChainId, ChangeHash, Key, ProjectId, PublicKey, Value, Verdict, Why,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::crypto::{self, EpochKey, HISTORY, Subkeys};
use crate::ticket::{Card, MAX_ARCH};
use crate::wire;

/// What a member may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Role {
    /// The project's one owner: edits, admits, removes, re-keys.
    Owner,
    /// Reads and edits.
    Editor,
    /// Reads and talks in threads: its edits are refused by every peer.
    Viewer,
    /// An agent (one a member's binbun signs for): edits as an editor
    /// does, told apart as an agent; limited as any member (made a viewer,
    /// removed).
    Agent,
    /// A store: given no key, writes nothing. Records may name one; this
    /// build takes them and links with no store.
    Store,
}

impl Role {
    /// Whether its edits are taken.
    pub fn edits(self) -> bool {
        match self {
            Self::Owner | Self::Editor | Self::Agent => true,
            Self::Viewer | Self::Store => false,
        }
    }

    /// Whether it may write `writes`.
    pub fn may(self, writes: Writes) -> bool {
        writes <= self.most()
    }

    /// The most it may write (none for a store).
    fn most(self) -> Writes {
        match self {
            Self::Owner | Self::Editor | Self::Agent => Writes::Edit,
            Self::Viewer => Writes::Talk,
            Self::Store => Writes::Nothing,
        }
    }

    /// The role named `name` (`editor`, `viewer`, `agent`), of those a
    /// member can be given here.
    ///
    /// # Errors
    ///
    /// No such role.
    pub fn given(name: &str) -> Result<Self, Error> {
        match name {
            "editor" => Ok(Self::Editor),
            "viewer" => Ok(Self::Viewer),
            "agent" => Ok(Self::Agent),
            _ => Err(Error::new(format!(
                "no role {name:?} (editor, viewer, agent)"
            ))),
        }
    }
}

/// What a change writes, the least first: what a role may write is all
/// up to its most.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Writes {
    /// Nothing (a store's).
    Nothing,
    /// Threads and posts: open, post, edit and delete one's own, resolve.
    Talk,
    /// Suggestions: made, superseded by their author.
    Suggest,
    /// Edits, and decisions on suggestions (accepted, dismissed, pending
    /// again).
    Edit,
}

impl Writes {
    /// The most a change of `body` writes.
    pub fn of(body: &Body) -> Self {
        body.ops
            .iter()
            .map(|op| match (&op.key, &op.value) {
                (Key::Thread(_) | Key::Post(_), _) => Self::Talk,
                (
                    Key::Suggestion(_),
                    Value::Suggestion(
                        SuggestionOp::New(_) | SuggestionOp::State(SuggestionState::Superseded(_)),
                    ),
                ) => Self::Suggest,
                _ => Self::Edit,
            })
            .max()
            .unwrap_or(Self::Nothing)
    }

    /// What of it a role that may not write it has refused, for people.
    fn refused(self) -> &'static str {
        match self {
            Self::Nothing | Self::Talk => "changes",
            Self::Suggest => "suggestions",
            Self::Edit => "edits",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Owner => "owner",
            Self::Editor => "editor",
            Self::Viewer => "viewer",
            Self::Agent => "agent",
            Self::Store => "store",
        })
    }
}

/// Per chain, the last change of it taken.
pub type Cut = BTreeMap<ChainId, u64>;

/// The most chains the first record lists from before the share.
pub const MAX_BEFORE: usize = 256;

/// The most changes of one chain the first record lists.
pub const MAX_THROUGH: u64 = 1 << 20;

/// The most chains a cut names, or a readmission closes.
pub const MAX_CUT: usize = 4096;

/// The most key wraps in a record: one per member who reads.
pub const MAX_WRAPS: usize = 256;

/// The bytes of a key wrap ([`crypto::wrap`]): an X25519 key, the epoch
/// key sealed and its tag.
pub const WRAP: usize = 80;

/// The most bytes of a record as signed and carried
/// ([`binbun_sync::wire::MAX_RECORD`]): its bytes, its signature and their
/// lengths.
pub const MAX_RECORD: usize = binbun_sync::wire::MAX_RECORD;

/// The bytes a signed record adds to its record's: the signature and the
/// lengths around it, at most.
const SIGNED: usize = 64 + 8;

/// The most members not removed, the owner among them.
pub const MAX_MEMBERS: usize = 256;

/// The most bytes of the chain with a record other than a removal
/// ([`Membership::bytes`]).
pub const MAX_CHAIN: usize = 8 << 20;

/// The most bytes of the chain with a removal: the room kept for
/// removals past [`MAX_CHAIN`].
pub const MAX_CHAIN_REMOVING: usize = 32 << 20;

/// The bytes of the chain past which the owner is warned that its room
/// for removals runs out ([`Membership::crowded`]).
pub const CROWDED: usize = 24 << 20;

/// The bytes a record's signature adds to the chain.
const SIGNATURE: usize = 64;

/// A cut as a record carries it.
pub type RecordCut = Map<ChainId, u64, MAX_CUT>;

/// The prefixes from before the share as the first record lists them:
/// per chain, the number it is taken up to and the hash of the change
/// there.
pub type Before = Bounded<(ChainId, u64, [u8; 32]), MAX_BEFORE>;

/// The binary a shared project annotates: the whole file's SHA-256 and,
/// of a universal Mach-O file, the slice opened. Every member's session is
/// on it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Binary {
    /// The file's SHA-256.
    pub sha256: [u8; 32],
    /// The slice's architecture, of a universal file.
    pub slice: Option<Text<MAX_ARCH>>,
}

impl Bounds for Binary {}

/// The most bytes of a binary sealed in a record.
const MAX_SEALED_BINARY: usize = 256;

/// `binary` sealed under epoch `key` of `project` (its `binary` subkey).
///
/// # Errors
///
/// No randomness; too large to seal.
fn seal_binary(
    key: &EpochKey,
    project: ProjectId,
    binary: &Binary,
) -> Result<Bytes<MAX_SEALED_BINARY, 1>, Error> {
    let plain = bounded::encode(binary, MAX_SEALED_BINARY)?;
    let sealed = crypto::seal_bare(&key.cipher(project, "binary"), &plain)?;
    Ok(Bytes::try_from(sealed)?)
}

/// The binary `sealed` holds under epoch `key` of `project`; `None` if it
/// does not open, or does not read.
pub(crate) fn open_binary(key: &EpochKey, project: ProjectId, sealed: &[u8]) -> Option<Binary> {
    let plain = crypto::open_bare(&key.cipher(project, "binary"), sealed)?;
    bounded::decode(&plain).ok()
}

/// What a membership record does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    /// The project shared: its owner, the owner's agreement key, the
    /// prefixes of the owner's chains from before the share that are of
    /// it, and the binary (sealed).
    Create {
        /// The owner.
        owner: PublicKey,
        /// The owner's agreement key.
        agreement: [u8; 32],
        /// The prefixes from before the share.
        before: Before,
        /// The binary the project annotates, sealed under epoch 0's key.
        binary: Bytes<MAX_SEALED_BINARY, 1>,
    },
    /// A member admitted.
    Add {
        /// Their identity key.
        member: PublicKey,
        /// Their agreement key.
        agreement: [u8; 32],
        /// Their role.
        role: Role,
    },
    /// A member's role changed: a grant, whose role their new chains
    /// have. One that lowers what they may write closes their chains of
    /// earlier grants past `cut` (at its start, a chain it does not name);
    /// one that does not lower carries an empty cut and closes nothing.
    SetRole {
        /// The member.
        member: PublicKey,
        /// The role from now.
        role: Role,
        /// Per chain of theirs, the last change that stands (lowering
        /// only).
        cut: RecordCut,
    },
    /// A member removed: their chains closed past `cut` (at its start, a
    /// chain it does not name); a new epoch, the binary sealed again under
    /// its key, the epoch before linked to it.
    Remove {
        /// The member.
        member: PublicKey,
        /// Per chain of theirs, the last change that stands.
        cut: RecordCut,
        /// The binary the project annotates, sealed under the new epoch's
        /// key.
        binary: Bytes<MAX_SEALED_BINARY, 1>,
        /// The history link ([`crypto::seal_history`]): the subkeys of
        /// the epoch before, sealed under the new epoch's.
        history: Exact<HISTORY>,
    },
    /// A member removed admitted again, the epoch's key wrapped to them: a
    /// grant. Their chains stay as the removal closed them; they write on
    /// a new chain, which names this record. It carries no cut.
    Readmit {
        /// Their identity key.
        member: PublicKey,
        /// Their agreement key (now).
        agreement: [u8; 32],
        /// Their role.
        role: Role,
    },
    /// The project's ownership given to a member, who signs every record
    /// after this one; the owner before becomes an editor. A grant of
    /// both: neither writes less, so it closes nothing.
    TransferOwner {
        /// The new owner.
        to: PublicKey,
    },
}

/// One record of the chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Its number, from 1.
    pub seq: u64,
    /// BLAKE3 of the record before (zeros for the first).
    pub prev: [u8; 32],
    /// What it does.
    pub op: Op,
    /// The epoch from this record on.
    pub epoch: u32,
    /// That epoch's key wrapped to members ([`crypto::wrap`]): to the
    /// owner at creation, to a reader added, to every reader at a new
    /// epoch.
    pub wraps: Bounded<(PublicKey, Exact<WRAP>), MAX_WRAPS>,
}

impl Bounds for Record {}

/// A record as signed by the owner: its encoding (postcard) and the
/// signature of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecord {
    /// `postcard(Record)`.
    pub bytes: Bytes<MAX_RECORD>,
    /// The owner's signature of `bytes`.
    #[serde(with = "wire::signature")]
    pub sig: Signature,
}

impl Bounds for SignedRecord {}

/// A record that set a member's entry: its number, the role it left
/// them (`None`: removed) and the cut it carries for their chains (a
/// removal's or a lowering's; none otherwise).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    record: u64,
    role: Option<Role>,
    cut: Cut,
}

/// A member as the chain says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Their agreement key.
    pub agreement: [u8; 32],
    /// The records that set their entry, in order: those with a role
    /// are grants.
    entries: Vec<Entry>,
}

impl Member {
    /// Their role now (`None`: removed).
    pub fn role(&self) -> Option<Role> {
        self.entries.last().and_then(|entry| entry.role)
    }

    /// Their grant now: the number of the record that set their entry, if
    /// it gives them a role.
    pub fn grant(&self) -> Option<u64> {
        let last = self.entries.last()?;
        last.role.map(|_| last.record)
    }

    /// The role record `grant` gave them, if it set their entry with one.
    fn granted(&self, grant: u64) -> Option<Role> {
        self.entries
            .iter()
            .find(|entry| entry.record == grant)
            .and_then(|entry| entry.role)
    }

    /// Where their chain `chain`, written under grant `grant`, is closed:
    /// the first change past what the first later record leaving them
    /// able to write less than the grant gave (a removal, a role lowered
    /// below it) lets stand, and that record's number. The change after
    /// the one its cut names, or the chain's start if the cut does not
    /// name it (none of its edits stand). `None` if no record closed it.
    /// Closing is final: no later record is consulted for the chain.
    fn closed(&self, chain: ChainId, grant: u64) -> Option<(u64, u64)> {
        let most = self.granted(grant)?.most();
        let closer = self
            .entries
            .iter()
            .filter(|entry| entry.record > grant)
            .find(|entry| entry.role.map_or(Writes::Nothing, Role::most) < most)?;
        let from = closer
            .cut
            .get(&chain)
            .map_or(1, |last| last.saturating_add(1));
        Some((from, closer.record))
    }

    /// Whether they were ever `role`.
    fn was(&self, role: Role) -> bool {
        self.entries.iter().any(|entry| entry.role == Some(role))
    }

    /// Their entry set by record `record` to `role`, carrying `cut`.
    fn set(&mut self, record: u64, role: Option<Role>, cut: Cut) {
        self.entries.push(Entry { record, role, cut });
    }
}

/// A shared project's membership chain, checked, and what it comes to.
#[derive(Clone, Debug)]
pub struct Membership {
    project: ProjectId,
    /// Who signs the next record ([`Self::signer`]).
    owner: PublicKey,
    /// Who signed the records, each from the number given on: the
    /// creator from 1, then each owner a transfer named from the record
    /// after it.
    signers: Vec<(u64, PublicKey)>,
    records: Vec<SignedRecord>,
    /// The last record's hash.
    hash: [u8; 32],
    /// The first record's hash: the share's genesis.
    genesis: Option<[u8; 32]>,
    /// The chain's bytes ([`Self::bytes`]).
    bytes: usize,
    members: BTreeMap<PublicKey, Member>,
    /// The members in the order the chain admitted them (the owner who
    /// created it first), removed ones too.
    admitted: Vec<PublicKey>,
    epoch: u32,
    /// The prefixes the first record lists.
    before: BTreeMap<ChainId, (u64, ChangeHash)>,
    /// The binary as the last record starting an epoch sealed it, and
    /// that epoch.
    binary: Option<(u32, Vec<u8>)>,
    /// Per epoch from 1, the hash of the record before the one that
    /// starts it, and that record's history link.
    links: Vec<([u8; 32], Exact<HISTORY>)>,
}

/// Whether `signed` is signed by `key`.
pub(crate) fn verifies(key: PublicKey, bytes: &[u8], sig: &Signature) -> bool {
    VerifyingKey::from_bytes(&key.0).is_ok_and(|key| key.verify_strict(bytes, sig).is_ok())
}

impl Membership {
    /// None yet of project `project`, owned by `owner` (as a ticket says):
    /// its records are to come.
    pub fn expecting(project: ProjectId, owner: PublicKey) -> Self {
        Self {
            project,
            owner,
            signers: vec![(1, owner)],
            records: Vec::new(),
            hash: [0; 32],
            genesis: None,
            bytes: 0,
            members: BTreeMap::new(),
            admitted: Vec::new(),
            epoch: 0,
            before: BTreeMap::new(),
            binary: None,
            links: Vec::new(),
        }
    }

    /// Project `project` shared by its owner (`secret`, agreement key
    /// `agreement`), with the prefixes `before` of the owner's chains from
    /// before the share (per chain, the number it is taken up to and the
    /// hash there), annotating `binary` (sealed under epoch 0's key): the
    /// chain's first record, to be taken by a chain expecting it
    /// ([`Self::expecting`] of the owner), and epoch 0's key.
    ///
    /// # Errors
    ///
    /// More than [`MAX_BEFORE`] prefixes, or one past [`MAX_THROUGH`]; no
    /// randomness.
    pub fn create(
        project: ProjectId,
        secret: &[u8; 32],
        agreement: [u8; 32],
        before: &BTreeMap<ChainId, (u64, ChangeHash)>,
        binary: &Binary,
    ) -> Result<(SignedRecord, EpochKey), Error> {
        let signer = SigningKey::from_bytes(secret);
        let owner = PublicKey(signer.verifying_key().to_bytes());
        let membership = Self::expecting(project, owner);
        let key = EpochKey::random()?;
        let wraps = vec![(owner, crypto::wrap(&key, project, 0, owner, &agreement)?)];
        let before: Vec<(ChainId, u64, [u8; 32])> = before
            .iter()
            .map(|(chain, (through, hash))| (*chain, *through, hash.0))
            .collect();
        let op = Op::Create {
            owner,
            agreement,
            before: Bounded::try_from(before)?,
            binary: seal_binary(&key, project, binary)?,
        };
        let first = membership.sign(&signer, op, 0, wraps)?;
        Ok((first, key))
    }

    /// The shared project.
    pub fn project(&self) -> ProjectId {
        self.project
    }

    /// Its owner now.
    pub fn owner(&self) -> PublicKey {
        self.owner
    }

    /// Who signs the next record, and whose signature every record is
    /// checked against as it is taken: the owner as the records before
    /// it leave the project (the creator, else the last a transfer named).
    pub fn signer(&self) -> PublicKey {
        self.owner
    }

    /// Who signs record `seq` of this chain, as the records before it
    /// leave the project (`None` at 0).
    pub fn signer_at(&self, seq: u64) -> Option<PublicKey> {
        self.signers
            .iter()
            .rev()
            .find(|(from, _)| *from <= seq)
            .map(|(_, signer)| *signer)
    }

    /// Whether `theirs`, a record another side holds at number `at` where
    /// this chain holds another, and that one are two records by one
    /// signer at one number of this chain: it reads, is numbered `at`,
    /// follows the record held before it (so is of this genesis: a first
    /// record of its own begins another share), has other bytes than the
    /// one held, and is signed by whoever signed that one. Anything less
    /// shows only that the chains do not match.
    pub fn conflicts(&self, at: u64, theirs: &SignedRecord) -> bool {
        let (Some(held), Some(before), Some(signer)) = (
            self.record(at),
            at.checked_sub(1)
                .filter(|before| *before > 0)
                .and_then(|before| self.record_hash(before)),
            self.signer_at(at),
        ) else {
            return false;
        };
        bounded::decode::<Record>(&theirs.bytes).is_ok_and(|record| {
            record.seq == at
                && record.prev == before
                && theirs.bytes != held.bytes
                && verifies(signer, &theirs.bytes, &theirs.sig)
        })
    }

    /// The share's genesis: the BLAKE3 of the first record's signed bytes
    /// (`None` before it).
    pub fn genesis(&self) -> Option<[u8; 32]> {
        self.genesis
    }

    /// The chain's bytes: each record's signed bytes and its signature.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether the chain is past [`CROWDED`] bytes: removals still fit up
    /// to [`MAX_CHAIN_REMOVING`], other records no longer do.
    pub fn crowded(&self) -> bool {
        self.bytes > CROWDED
    }

    /// How many records it has: the last one's number.
    pub fn seq(&self) -> u64 {
        self.records.len() as u64
    }

    /// Its head: the last record's number and hash (zeros before the
    /// first).
    pub fn head(&self) -> (u64, [u8; 32]) {
        (self.seq(), self.hash)
    }

    /// The hash of record `seq` (zeros at 0), if it has one.
    pub fn record_hash(&self, seq: u64) -> Option<[u8; 32]> {
        if seq == 0 {
            return Some([0; 32]);
        }
        let index = usize::try_from(seq - 1).ok()?;
        let signed = self.records.get(index)?;
        Some(*blake3::hash(&signed.bytes).as_bytes())
    }

    /// Record `seq`, if it has one.
    pub fn record(&self, seq: u64) -> Option<&SignedRecord> {
        self.records.get(usize::try_from(seq.checked_sub(1)?).ok()?)
    }

    /// The records past number `known`, in order.
    pub fn since(&self, known: u64) -> &[SignedRecord] {
        let from = usize::try_from(known).unwrap_or(usize::MAX);
        self.records.get(from..).unwrap_or_default()
    }

    /// The epoch now.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The binary the project annotates, opened with the key of the epoch
    /// that last sealed it, of `keys`: `None` before the first record,
    /// without that key, or if it does not open.
    pub fn binary(&self, keys: &BTreeMap<u32, EpochKey>) -> Option<Binary> {
        let (epoch, sealed) = self.binary.as_ref()?;
        open_binary(keys.get(epoch)?, self.project, sealed)
    }

    /// The epoch whose key sealed the binary last (`None` before the
    /// first record).
    pub fn binary_epoch(&self) -> Option<u32> {
        self.binary.as_ref().map(|(epoch, _)| *epoch)
    }

    /// The prefixes of chains from before the share its first record
    /// lists: per chain, the number taken up to and the hash there.
    pub fn before(&self) -> &BTreeMap<ChainId, (u64, ChangeHash)> {
        &self.before
    }

    /// The members ever admitted (the owner first among them), removed
    /// ones too.
    pub fn members(&self) -> &BTreeMap<PublicKey, Member> {
        &self.members
    }

    /// The members ever admitted in the order the chain admitted them (the
    /// creator first), removed ones too, each once (a member readmitted
    /// keeps their place): the same on every copy of the chain.
    pub fn admitted(&self) -> &[PublicKey] {
        &self.admitted
    }

    /// `member`'s role now; `None` if not a member (or removed).
    pub fn role(&self, member: PublicKey) -> Option<Role> {
        self.members.get(&member).and_then(Member::role)
    }

    /// Who owns or owned the project: who may delete anyone's post
    /// (`binbun_session::Session::set_owners`).
    pub fn owners(&self) -> Vec<PublicKey> {
        self.members
            .iter()
            .filter(|(_, member)| member.was(Role::Owner))
            .map(|(key, _)| *key)
            .collect()
    }

    /// Whether `member` was a member and is removed.
    pub fn removed(&self, member: PublicKey) -> bool {
        self.members
            .get(&member)
            .is_some_and(|known| known.role().is_none())
    }

    /// The number of the record that removed `member`, if they are
    /// removed now.
    pub fn removal(&self, member: PublicKey) -> Option<u64> {
        let last = self.members.get(&member)?.entries.last()?;
        last.role.is_none().then_some(last.record)
    }

    /// `member`'s grant now: the number of the record that set their
    /// entry, if it gives them a role (sync §4.3). A chain they begin now
    /// names it.
    pub fn grant(&self, member: PublicKey) -> Option<u64> {
        self.members.get(&member).and_then(Member::grant)
    }

    /// Whether making `member` a `role` leaves them able to write less
    /// than they may now: the only role change that carries a cut.
    fn lowers(&self, member: PublicKey, role: Role) -> bool {
        self.role(member)
            .is_some_and(|before| role.most() < before.most())
    }

    /// What may be decided now of change `seq` of chain `chain`, by
    /// `author`, writing `writes`, on a chain whose start names record
    /// `grant` (sync §4.2, §4.3): a function of the chain's start and the
    /// membership chain alone. Not yet (declined, no stop) while record
    /// `grant` is not here; never if it does not set its author's entry
    /// with a role, if the change is at or past where a later record
    /// closed the chain, or if the grant's role may not write it; else
    /// taken.
    pub fn judge(
        &self,
        author: PublicKey,
        chain: ChainId,
        seq: u64,
        grant: u64,
        writes: Writes,
    ) -> Verdict {
        if grant > self.seq() {
            return Verdict::Decline;
        }
        let role = self
            .members
            .get(&author)
            .and_then(|member| Some((member, member.granted(grant)?)));
        let Some((member, role)) = role else {
            return Verdict::Never(Why::new(&format!(
                "membership record {grant} gives its author {author} no role"
            )));
        };
        if let Some((from, record)) = member.closed(chain, grant)
            && seq >= from
        {
            return Verdict::Never(Why::new(&format!(
                "membership record {record} closed its author {author}'s chain before it"
            )));
        }
        if role.may(writes) {
            Verdict::Admit
        } else {
            Verdict::Never(Why::new(&format!(
                "its author {author} writes it as a {role}: {} refused",
                writes.refused()
            )))
        }
    }

    /// The chains to freeze, and from which change: each chain `known`
    /// (with its author and grant) that a record after its grant closed
    /// (sync §4.3), from the first change past what that record lets
    /// stand. A peer that took some of those before the record reached it
    /// drops them; every peer refuses the rest.
    pub fn freezes(&self, known: &[(ChainId, PublicKey, u64)]) -> BTreeMap<ChainId, u64> {
        known
            .iter()
            .filter_map(|(chain, author, grant)| {
                let (from, _) = self.members.get(author)?.closed(*chain, *grant)?;
                Some((*chain, from))
            })
            .collect()
    }

    /// The chains record `record`, the next ([`Self::verify`]), freezes,
    /// and from which change: of the chains `known` (each with its author
    /// and grant), those of an author it names that it closes, as they
    /// stand after it.
    pub fn caused(
        &self,
        record: &Record,
        known: &[(ChainId, PublicKey, u64)],
    ) -> BTreeMap<ChainId, u64> {
        let mut freezes = BTreeMap::new();
        for (author, member) in self.effect(record) {
            for (chain, _, grant) in known.iter().filter(|(_, known, _)| *known == author) {
                if let Some((from, at)) = member.closed(*chain, *grant)
                    && at == record.seq
                {
                    freezes.insert(*chain, from);
                }
            }
        }
        freezes
    }

    /// Takes record `signed`, the next: verified ([`Self::verify`]),
    /// then committed. The record.
    ///
    /// # Errors
    ///
    /// It fails a check; nothing is taken then.
    pub fn take(&mut self, signed: &SignedRecord) -> Result<Record, Error> {
        let record = self.verify(signed)?;
        self.commit(signed, &record);
        Ok(record)
    }

    /// Record `signed`, if it can be the next: it reads within its
    /// bounds, follows the last, is signed by [`Self::signer`], does what
    /// may be done and fits the chain ([`Self::check`]). Nothing is taken.
    ///
    /// # Errors
    ///
    /// It fails a check.
    pub fn verify(&self, signed: &SignedRecord) -> Result<Record, Error> {
        let record: Record = bounded::decode(&signed.bytes).map_err(|error| {
            Error::new(format!("a membership record that does not read: {error}"))
        })?;
        if record.seq != self.seq() + 1 || record.prev != self.hash {
            return Err(Error::new(format!(
                "membership record {} does not follow record {}",
                record.seq,
                self.seq()
            )));
        }
        if !verifies(self.signer(), &signed.bytes, &signed.sig) {
            return Err(Error::new(format!(
                "membership record {} is not signed by the owner",
                record.seq
            )));
        }
        if signed.bytes.len() + SIGNED > MAX_RECORD {
            return Err(Error::new(format!(
                "membership record {}: past {} KiB as signed",
                record.seq,
                MAX_RECORD >> 10
            )));
        }
        self.check(&record, signed.bytes.len() + SIGNATURE)?;
        Ok(record)
    }

    /// Takes `signed`, whose record is `record`, as the next: both as
    /// [`Self::verify`] gave them against this chain as it stands.
    pub(crate) fn commit(&mut self, signed: &SignedRecord, record: &Record) {
        self.apply(record);
        self.records.push(signed.clone());
        self.hash = *blake3::hash(&signed.bytes).as_bytes();
        self.genesis.get_or_insert(self.hash);
        self.bytes += signed.bytes.len() + SIGNATURE;
    }

    /// Why `record`, of `size` bytes signed, cannot be taken now, if it
    /// cannot. What its type bounds (a record's bytes, each wrap's, each
    /// cut's chains, the binary sealed, the history link) was checked as
    /// it was read; what depends on the chain is checked here.
    fn check(&self, record: &Record, size: usize) -> Result<(), Error> {
        let refuse = |why: String| {
            Err(Error::new(format!(
                "membership record {}: {why}",
                record.seq
            )))
        };
        let most = match record.op {
            Op::Remove { .. } => MAX_CHAIN_REMOVING,
            Op::Create { .. }
            | Op::Add { .. }
            | Op::SetRole { .. }
            | Op::Readmit { .. }
            | Op::TransferOwner { .. } => MAX_CHAIN,
        };
        if self.bytes.saturating_add(size) > most {
            return refuse(format!(
                "the chain with it would be past {} MiB",
                most >> 20
            ));
        }
        let present = self
            .members
            .values()
            .filter(|member| member.role().is_some())
            .count();
        if matches!(record.op, Op::Add { .. } | Op::Readmit { .. }) && present >= MAX_MEMBERS {
            return refuse(format!("{MAX_MEMBERS} members already"));
        }
        let readers = |extra: Option<PublicKey>, gone: Option<PublicKey>| -> BTreeSet<PublicKey> {
            self.members
                .iter()
                .filter(|(key, member)| Some(**key) != gone && member.role().is_some_and(reads))
                .map(|(key, _)| *key)
                .chain(extra)
                .collect()
        };
        let wrapped: BTreeSet<PublicKey> = record.wraps.iter().map(|(key, _)| *key).collect();
        if let Op::Create { before, .. } = &record.op
            && let Err(why) = check_before(before)
        {
            return refuse(why);
        }
        let (epoch, wanted) = match &record.op {
            Op::Create { owner, .. } => {
                if record.seq != 1 || *owner != self.owner {
                    return refuse("a creation not first, or not by the owner".to_owned());
                }
                (0, BTreeSet::from([*owner]))
            }
            _ if record.seq == 1 => return refuse("the first record creates nothing".to_owned()),
            Op::Add { member, role, .. } => {
                if self.members.contains_key(member) {
                    return refuse(format!("{member} is or was a member already"));
                }
                if !given(*role) {
                    return refuse(format!("a member is not made {role} yet"));
                }
                (self.epoch, keyed(*member, *role))
            }
            Op::SetRole { member, role, cut } => {
                if self.role(*member).is_none() || *member == self.owner {
                    return refuse(format!("{member} is no member whose role can change"));
                }
                if !given(*role) {
                    return refuse(format!("a member is not made {role} yet"));
                }
                // A store holds no key, a reader one: neither becomes the
                // other.
                if (*role == Role::Store) != (self.role(*member) == Some(Role::Store)) {
                    return refuse(format!("{member} cannot become a {role} or stop being one"));
                }
                // Only a record that lowers closes chains: one that does
                // not carries no cut (sync §4.3).
                if !self.lowers(*member, *role) && !cut.is_empty() {
                    return refuse(format!("{member} writes no less as a {role}: no cut"));
                }
                (self.epoch, BTreeSet::new())
            }
            Op::Remove { member, .. } => {
                if self.role(*member).is_none() || *member == self.owner {
                    return refuse(format!("{member} is no member who can be removed"));
                }
                (self.epoch + 1, readers(None, Some(*member)))
            }
            Op::Readmit { member, role, .. } => {
                if !self.removed(*member) {
                    return refuse(format!("{member} is no member removed"));
                }
                if !given(*role) {
                    return refuse(format!("a member is not made {role} yet"));
                }
                (self.epoch, keyed(*member, *role))
            }
            Op::TransferOwner { to, .. } => {
                if self.role(*to).is_none_or(|role| role == Role::Store) || *to == self.owner {
                    return refuse(format!("{to} is no member who can own the project"));
                }
                (self.epoch, BTreeSet::new())
            }
        };
        if record.epoch != epoch || wrapped != wanted || wrapped.len() != record.wraps.len() {
            return refuse("its epoch or key wraps are not the ones it needs".to_owned());
        }
        Ok(())
    }

    /// The members `record` names, as they stand after it.
    fn effect(&self, record: &Record) -> Vec<(PublicKey, Member)> {
        let seq = record.seq;
        let new = |agreement: [u8; 32], role: Role| Member {
            agreement,
            entries: vec![Entry {
                record: seq,
                role: Some(role),
                cut: Cut::new(),
            }],
        };
        let changed = |key: PublicKey, role: Option<Role>, cut: Cut| {
            let mut member = self.members.get(&key)?.clone();
            member.set(seq, role, cut);
            Some((key, member))
        };
        match &record.op {
            Op::Create {
                owner, agreement, ..
            } => vec![(*owner, new(*agreement, Role::Owner))],
            Op::Add {
                member,
                agreement,
                role,
                ..
            } => vec![(*member, new(*agreement, *role))],
            Op::SetRole { member, role, cut } => changed(*member, Some(*role), Cut::clone(cut))
                .into_iter()
                .collect(),
            Op::Remove { member, cut, .. } => changed(*member, None, Cut::clone(cut))
                .into_iter()
                .collect(),
            Op::Readmit {
                member,
                agreement,
                role,
            } => changed(*member, Some(*role), Cut::new())
                .map(|(key, member)| {
                    (
                        key,
                        Member {
                            agreement: *agreement,
                            ..member
                        },
                    )
                })
                .into_iter()
                .collect(),
            Op::TransferOwner { to } => [
                changed(self.owner, Some(Role::Editor), Cut::new()),
                changed(*to, Some(Role::Owner), Cut::new()),
            ]
            .into_iter()
            .flatten()
            .collect(),
        }
    }

    /// What `record` does, done.
    fn apply(&mut self, record: &Record) {
        for (key, member) in self.effect(record) {
            if self.members.insert(key, member).is_none() {
                self.admitted.push(key);
            }
        }
        self.epoch = record.epoch;
        match &record.op {
            Op::Create { before, binary, .. } => {
                self.before = before
                    .iter()
                    .map(|(chain, through, hash)| (*chain, (*through, ChangeHash(*hash))))
                    .collect();
                self.binary = Some((record.epoch, binary.to_vec()));
            }
            Op::Add { .. } | Op::Readmit { .. } | Op::SetRole { .. } => {}
            Op::Remove {
                binary, history, ..
            } => {
                self.binary = Some((record.epoch, binary.to_vec()));
                self.links.push((record.prev, *history));
            }
            Op::TransferOwner { to, .. } => {
                self.owner = *to;
                self.signers.push((record.seq + 1, *to));
            }
        }
    }

    /// Signs `op` (the owner's `signer`) at epoch `epoch` with `wraps` as
    /// the next record, verified as one that can be taken
    /// ([`Self::verify`]); not taken.
    ///
    /// # Errors
    ///
    /// Its wraps or its bytes are past a record's bounds; it is not one
    /// that can be taken.
    fn sign(
        &self,
        signer: &SigningKey,
        op: Op,
        epoch: u32,
        wraps: Vec<(PublicKey, Vec<u8>)>,
    ) -> Result<SignedRecord, Error> {
        let wraps = wraps
            .into_iter()
            .map(|(member, wrapped)| Ok((member, Exact::try_from(wrapped.as_slice())?)))
            .collect::<Result<Vec<_>, bounded::Error>>()?;
        let record = Record {
            seq: self.seq() + 1,
            prev: self.hash,
            op,
            epoch,
            wraps: Bounded::try_from(wraps)?,
        };
        let bytes = Bytes::try_from(bounded::encode(&record, MAX_RECORD)?)?;
        let sig = signer.sign(&bytes);
        let made = SignedRecord { bytes, sig };
        self.verify(&made)?;
        Ok(made)
    }

    /// The signing key from `secret`, if it is [`Self::signer`]'s.
    fn owner_signer(&self, secret: &[u8; 32]) -> Result<SigningKey, Error> {
        let signer = SigningKey::from_bytes(secret);
        if PublicKey(signer.verifying_key().to_bytes()) == self.signer() {
            Ok(signer)
        } else {
            Err(Error::new("only the project's owner changes its members"))
        }
    }

    /// Admits `member` (agreement key `agreement`) as `role`, the epoch's
    /// `key` wrapped to them; by the owner (`secret`). The record, to be
    /// taken.
    ///
    /// # Errors
    ///
    /// Not the owner; a member already; a role not given yet.
    pub fn add(
        &self,
        secret: &[u8; 32],
        key: &EpochKey,
        member: PublicKey,
        agreement: [u8; 32],
        role: Role,
    ) -> Result<SignedRecord, Error> {
        let signer = self.owner_signer(secret)?;
        let wraps = if reads(role) {
            vec![(
                member,
                crypto::wrap(key, self.project, self.epoch, member, &agreement)?,
            )]
        } else {
            Vec::new()
        };
        let op = Op::Add {
            member,
            agreement,
            role,
        };
        self.sign(&signer, op, self.epoch, wraps)
    }

    /// Admits `card`'s member, removed before, again as `role`: the
    /// epoch's `key` wrapped to them; their chains stay as the removal
    /// closed them, and they write on a new one, which names this record.
    /// By the owner (`secret`). The record, to be taken.
    ///
    /// # Errors
    ///
    /// Not the owner; not a member removed; a role not given yet.
    pub fn readmit(
        &self,
        secret: &[u8; 32],
        key: &EpochKey,
        card: &Card,
        role: Role,
    ) -> Result<SignedRecord, Error> {
        let signer = self.owner_signer(secret)?;
        let wraps = if reads(role) {
            vec![(
                card.key,
                crypto::wrap(key, self.project, self.epoch, card.key, &card.agreement)?,
            )]
        } else {
            Vec::new()
        };
        let op = Op::Readmit {
            member: card.key,
            agreement: card.agreement,
            role,
        };
        self.sign(&signer, op, self.epoch, wraps)
    }

    /// Gives the project to member `to`; the owner (`secret`) becomes an
    /// editor and signs nothing after. Neither writes less: it closes no
    /// chain. The record, to be taken.
    ///
    /// # Errors
    ///
    /// Not the owner; `to` no member, or the owner.
    pub fn transfer(&self, secret: &[u8; 32], to: PublicKey) -> Result<SignedRecord, Error> {
        let signer = self.owner_signer(secret)?;
        self.sign(&signer, Op::TransferOwner { to }, self.epoch, Vec::new())
    }

    /// Makes `member` a `role` from now: their new chains have it. If it
    /// lowers what they may write, their chains of earlier grants close
    /// past `cut` (at their start, those it does not name); otherwise the
    /// record carries no cut and closes nothing. By the owner (`secret`).
    /// The record, to be taken.
    ///
    /// # Errors
    ///
    /// Not the owner; not a member, or the owner; a role not given yet;
    /// more than [`MAX_CUT`] chains cut.
    pub fn set_role(
        &self,
        secret: &[u8; 32],
        member: PublicKey,
        role: Role,
        cut: Cut,
    ) -> Result<SignedRecord, Error> {
        let signer = self.owner_signer(secret)?;
        let cut = if self.lowers(member, role) {
            cut
        } else {
            Cut::new()
        };
        self.sign(
            &signer,
            Op::SetRole {
                member,
                role,
                cut: RecordCut::try_from(cut)?,
            },
            self.epoch,
            Vec::new(),
        )
    }

    /// Removes `member`, their changes past `cut` refused, and starts the
    /// next epoch, its new key wrapped to every reader left and sealing
    /// `binary` again, the subkeys of the epoch now (its `key`) linked to
    /// it. By the owner (`secret`). The record, to be taken, and the new
    /// key.
    ///
    /// # Errors
    ///
    /// Not the owner; not a member, or the owner; no randomness.
    pub fn remove(
        &self,
        secret: &[u8; 32],
        key: &EpochKey,
        member: PublicKey,
        cut: Cut,
        binary: &Binary,
    ) -> Result<(SignedRecord, EpochKey), Error> {
        let signer = self.owner_signer(secret)?;
        let new = EpochKey::random()?;
        let epoch = self.epoch + 1;
        let wraps = self
            .members
            .iter()
            .filter(|(known, entry)| **known != member && entry.role().is_some_and(reads))
            .map(|(known, entry)| {
                crypto::wrap(&new, self.project, epoch, *known, &entry.agreement)
                    .map(|wrapped| (*known, wrapped))
            })
            .collect::<Result<_, _>>()?;
        let genesis = self
            .genesis
            .ok_or_else(|| Error::new("no membership chain held yet"))?;
        let history = crypto::seal_history(
            &new.subkeys(self.project),
            &genesis,
            epoch,
            &self.hash,
            &key.subkeys(self.project),
        )?;
        let op = Op::Remove {
            member,
            cut: RecordCut::try_from(cut)?,
            binary: seal_binary(&new, self.project, binary)?,
            history: Exact::from(history),
        };
        let record = self.sign(&signer, op, epoch, wraps)?;
        Ok((record, new))
    }

    /// The subkeys of every epoch before epoch `epoch`, by epoch, derived
    /// from that epoch's `key` through the history links, one AEAD per
    /// epoch walked down; never an earlier epoch's key. Where `held` has
    /// an earlier epoch's key, the subkeys the link gives are checked
    /// against those it derives.
    ///
    /// # Errors
    ///
    /// `epoch` is not one of the chain's; a link does not open, so the
    /// history before that epoch cannot be derived; or it gives other
    /// subkeys than a key held derives.
    pub fn history(
        &self,
        epoch: u32,
        key: &EpochKey,
        held: &BTreeMap<u32, EpochKey>,
    ) -> Result<BTreeMap<u32, Subkeys>, Error> {
        if epoch > self.epoch || self.records.is_empty() {
            return Err(Error::new(format!("no epoch {epoch} in the chain")));
        }
        let mut earlier = BTreeMap::new();
        let mut later = key.subkeys(self.project);
        for at in (1..=epoch).rev() {
            let opened = self.open_link(at, &later)?;
            if let Some(own) = held.get(&(at - 1)) {
                self.compare_link(at, own, &opened)?;
            }
            earlier.insert(at - 1, opened.clone());
            later = opened;
        }
        Ok(earlier)
    }

    /// Whether the history link of epoch `epoch` (≥ 1), opened with that
    /// epoch's `key`, seals the subkeys `earlier` (epoch `epoch` − 1's key)
    /// derives: what a member holding both checks.
    ///
    /// # Errors
    ///
    /// No record starts that epoch; its link does not open, or seals
    /// other subkeys.
    pub fn check_history(
        &self,
        epoch: u32,
        key: &EpochKey,
        earlier: &EpochKey,
    ) -> Result<(), Error> {
        let opened = self.open_link(epoch, &key.subkeys(self.project))?;
        self.compare_link(epoch, earlier, &opened)
    }

    /// The subkeys of epoch `epoch` − 1 that the history link of epoch
    /// `epoch` (≥ 1) seals under that epoch's subkeys `later`.
    fn open_link(&self, epoch: u32, later: &Subkeys) -> Result<Subkeys, Error> {
        let (prev, link) = epoch
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.links.get(index))
            .ok_or_else(|| Error::new(format!("no record starts epoch {epoch}")))?;
        let genesis = self
            .genesis
            .ok_or_else(|| Error::new("no membership chain held yet"))?;
        crypto::open_history(later, &genesis, epoch, prev, link.as_array())
            .ok_or_else(|| Error::new(format!("history before epoch {epoch} cannot be derived")))
    }

    /// Whether `opened`, from the history link of epoch `epoch`, are the
    /// subkeys `earlier` (the key of the epoch before) derives.
    fn compare_link(&self, epoch: u32, earlier: &EpochKey, opened: &Subkeys) -> Result<(), Error> {
        if earlier.subkeys(self.project) == *opened {
            Ok(())
        } else {
            Err(Error::new(format!(
                "the history link of epoch {epoch} seals other keys than epoch {}'s",
                epoch - 1
            )))
        }
    }
}

/// Why the prefixes a first record lists, `before`, are not ones it may
/// list, if they are not: a chain twice, or a prefix of no change or past
/// [`MAX_THROUGH`].
fn check_before(before: &Before) -> Result<(), String> {
    let chains: BTreeSet<ChainId> = before.iter().map(|(chain, ..)| *chain).collect();
    if chains.len() != before.len() {
        return Err("a chain listed twice".to_owned());
    }
    if before
        .iter()
        .any(|(_, through, _)| !(1..=MAX_THROUGH).contains(through))
    {
        return Err(format!(
            "a prefix listed of no change, or past {MAX_THROUGH}"
        ));
    }
    Ok(())
}

/// Whether `role` receives the epochs' keys.
fn reads(role: Role) -> bool {
    match role {
        Role::Owner | Role::Editor | Role::Viewer | Role::Agent => true,
        Role::Store => false,
    }
}

/// Whether a member can be given `role`: every role but the owner's,
/// which only a transfer gives.
fn given(role: Role) -> bool {
    match role {
        Role::Editor | Role::Viewer | Role::Agent | Role::Store => true,
        Role::Owner => false,
    }
}

/// Whom a record admitting `member` as `role` wraps the epoch's key to:
/// them, unless a store, which is given none.
fn keyed(member: PublicKey, role: Role) -> BTreeSet<PublicKey> {
    if reads(role) {
        BTreeSet::from([member])
    } else {
        BTreeSet::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use binbun_bounded::{self as bounded, Bounded, Bytes, Exact};
    use binbun_session::identity::Identity;
    use binbun_session::journal::{
        Body, ChainId, ChangeHash, Head, ProjectId, PublicKey, SignedChange, SignedHead, Signer,
        Verdict,
    };
    use binbun_sync::envelope::Envelope;
    use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
    use ed25519_dalek::{Signature, Signer as _, SigningKey};

    use super::{
        Binary, Cut, HISTORY, MAX_BEFORE, MAX_CHAIN, MAX_CHAIN_REMOVING, MAX_CUT, MAX_MEMBERS,
        MAX_RECORD, MAX_THROUGH, Membership, Op, Record, Role, SignedRecord, WRAP, Writes,
        seal_binary,
    };
    use crate::crypto::EpochKey;
    use crate::ticket::Card;
    use crate::{Error, crypto};

    const PROJECT: ProjectId = ProjectId([1; 16]);
    const CHAIN: ChainId = ChainId([2; 16]);

    fn binary() -> Binary {
        Binary {
            sha256: [3; 32],
            slice: None,
        }
    }

    /// A chain `owner` creates, and epoch 0's key.
    fn created(owner: &Identity) -> (Membership, EpochKey) {
        let (first, key) = Membership::create(
            PROJECT,
            &owner.secret(),
            owner.agreement(),
            &BTreeMap::new(),
            &binary(),
        )
        .unwrap();
        let mut chain = Membership::expecting(PROJECT, owner.public());
        chain.take(&first).unwrap();
        (chain, key)
    }

    /// `signed`, taken by `chain`.
    fn took(signed: Result<SignedRecord, Error>, chain: &mut Membership) -> SignedRecord {
        let signed = signed.unwrap();
        chain.take(&signed).unwrap();
        signed
    }

    /// `who` admitted to `chain` as `role` by `owner`, `key` the epoch's.
    fn admitted(
        chain: &mut Membership,
        owner: &Identity,
        key: &EpochKey,
        who: &Identity,
        role: Role,
    ) -> SignedRecord {
        let signed = chain.add(&owner.secret(), key, who.public(), who.agreement(), role);
        took(signed, chain)
    }

    #[test]
    fn the_binary_is_sealed_from_whoever_holds_no_key_and_again_at_each_new_epoch() {
        let (owner, ann) = (
            Identity::ephemeral().unwrap(),
            Identity::ephemeral().unwrap(),
        );
        let (mut chain, epoch0) = created(&owner);
        took(
            chain.add(
                &owner.secret(),
                &epoch0,
                ann.public(),
                ann.agreement(),
                Role::Editor,
            ),
            &mut chain,
        );
        let (removal, epoch1) = chain
            .remove(
                &owner.secret(),
                &epoch0,
                ann.public(),
                Cut::new(),
                &binary(),
            )
            .unwrap();
        chain.take(&removal).unwrap();
        // The records hold no digest of it, in any epoch.
        let digest = binary().sha256;
        for signed in chain.since(0) {
            assert!(!signed.bytes.windows(32).any(|bytes| bytes == digest));
        }
        // A copy (a store's) without keys reads none; the key of the
        // epoch that sealed it last reads it, the one before does not.
        let mut copy = Membership::expecting(PROJECT, owner.public());
        for signed in chain.since(0) {
            copy.take(signed).unwrap();
        }
        assert_eq!(copy.binary(&BTreeMap::new()), None);
        assert_eq!(copy.binary(&BTreeMap::from([(0, epoch0)])), None);
        assert_eq!(copy.binary(&BTreeMap::from([(1, epoch1)])), Some(binary()));
    }

    #[test]
    fn the_first_record_lists_bounded_prefixes_each_chain_once_on_every_copy() {
        let owner = Identity::ephemeral().unwrap();
        let listed = BTreeMap::from([
            (CHAIN, (7, ChangeHash([4; 32]))),
            (ChainId([5; 16]), (MAX_THROUGH, ChangeHash([6; 32]))),
        ]);
        let (first, _) = Membership::create(
            PROJECT,
            &owner.secret(),
            owner.agreement(),
            &listed,
            &binary(),
        )
        .unwrap();
        // A copy from the record alone lists the same prefixes.
        let mut copy = Membership::expecting(PROJECT, owner.public());
        copy.take(&first).unwrap();
        assert_eq!(copy.before(), &listed);
        // More chains than the bound: nothing is signed.
        let many: BTreeMap<ChainId, (u64, ChangeHash)> = (0..=MAX_BEFORE)
            .map(|n| {
                let n = u16::try_from(n).unwrap().to_le_bytes();
                (
                    ChainId([n[0], n[1], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    (1, ChangeHash([0; 32])),
                )
            })
            .collect();
        let refused = Membership::create(
            PROJECT,
            &owner.secret(),
            owner.agreement(),
            &many,
            &binary(),
        );
        assert!(refused.is_err());
        // A first record the owner signed listing a chain twice, a prefix
        // of no change, or one past the bound, is refused by every copy.
        let signed = |before: Vec<(ChainId, u64, [u8; 32])>| {
            let key = EpochKey::random().unwrap();
            let wrap = crypto::wrap(&key, PROJECT, 0, owner.public(), &owner.agreement()).unwrap();
            let record = Record {
                seq: 1,
                prev: [0; 32],
                op: Op::Create {
                    owner: owner.public(),
                    agreement: owner.agreement(),
                    before: Bounded::try_from(before).unwrap(),
                    binary: seal_binary(&key, PROJECT, &binary()).unwrap(),
                },
                epoch: 0,
                wraps: Bounded::truncated(vec![(
                    owner.public(),
                    Exact::try_from(wrap.as_slice()).unwrap(),
                )]),
            };
            let bytes = Bytes::try_from(bounded::encode(&record, MAX_RECORD).unwrap()).unwrap();
            let sig = SigningKey::from_bytes(&owner.secret()).sign(&bytes);
            SignedRecord { bytes, sig }
        };
        for before in [
            vec![(CHAIN, 1, [0; 32]), (CHAIN, 2, [0; 32])],
            vec![(CHAIN, 0, [0; 32])],
            vec![(CHAIN, MAX_THROUGH + 1, [0; 32])],
        ] {
            let mut copy = Membership::expecting(PROJECT, owner.public());
            assert!(copy.take(&signed(before)).is_err());
        }
        let mut copy = Membership::expecting(PROJECT, owner.public());
        copy.take(&signed(vec![(CHAIN, MAX_THROUGH, [0; 32])]))
            .unwrap();
    }

    /// What `view` makes of the chain the test below writes (records: 1
    /// the owner's, 2 Ann an editor, 3 Bob a viewer, 4 Bob an editor, 5
    /// Ann removed past her fifth change of `CHAIN`, 6 Cat a viewer).
    fn judged(view: &Membership, owner: &Identity, [ann, bob, cat]: [&Identity; 3]) {
        let edit = Writes::Edit;
        let never = |verdict: Verdict| matches!(verdict, Verdict::Never(_));
        // Bob's chain of his viewer's grant talks, and neither suggests
        // nor edits, for good: the raise gave its rights to a new chain.
        assert!(never(view.judge(bob.public(), CHAIN, 3, 3, edit)));
        assert_eq!(
            view.judge(bob.public(), CHAIN, 9, 3, Writes::Talk),
            Verdict::Admit
        );
        assert!(never(view.judge(
            bob.public(),
            CHAIN,
            3,
            3,
            Writes::Suggest
        )));
        let other = ChainId([7; 16]);
        assert_eq!(view.judge(bob.public(), other, 4, 4, edit), Verdict::Admit);
        // Ann's chain the removal names stands to its fifth change; one it
        // does not name is closed at its start.
        assert_eq!(view.judge(ann.public(), CHAIN, 5, 2, edit), Verdict::Admit);
        assert!(never(view.judge(ann.public(), CHAIN, 6, 2, Writes::Talk)));
        let unseen = ChainId([8; 16]);
        assert!(never(view.judge(
            ann.public(),
            unseen,
            1,
            2,
            Writes::Nothing
        )));
        assert!(never(view.judge(ann.public(), unseen, 2, 2, edit)));
        // A role refusal is for good: no later record changes a chain's.
        assert!(never(view.judge(cat.public(), CHAIN, 9, 6, edit)));
        // A grant that does not set its author's entry: never. One not
        // here yet: declined, no stop.
        assert!(never(view.judge(bob.public(), other, 2, 2, edit)));
        assert!(never(view.judge(PublicKey([9; 32]), CHAIN, 2, 2, edit)));
        assert_eq!(
            view.judge(PublicKey([9; 32]), CHAIN, 1, 7, Writes::Nothing),
            Verdict::Decline
        );
        assert_eq!(
            view.judge(owner.public(), CHAIN, 1_000, 1, edit),
            Verdict::Admit
        );
        assert_eq!(
            (view.grant(bob.public()), view.grant(ann.public())),
            (Some(4), None)
        );
        assert!(view.removed(ann.public()));
        assert_eq!(view.epoch(), 1);
        assert_eq!(view.owners(), [owner.public()]);
    }

    #[test]
    fn roles_cuts_and_epochs_as_the_chain_says_on_every_copy() {
        let (owner, ann, bob, cat) = (
            Identity::ephemeral().unwrap(),
            Identity::ephemeral().unwrap(),
            Identity::ephemeral().unwrap(),
            Identity::ephemeral().unwrap(),
        );
        let (mut chain, epoch0) = created(&owner);
        let mut copy = Membership::expecting(PROJECT, owner.public());
        let add_ann = admitted(&mut chain, &owner, &epoch0, &ann, Role::Editor);
        let add_bob = admitted(&mut chain, &owner, &epoch0, &bob, Role::Viewer);
        // Only the owner writes the chain.
        assert!(
            chain
                .set_role(&ann.secret(), bob.public(), Role::Editor, Cut::new())
                .is_err()
        );
        // Bob made an editor: a raise carries no cut, whatever the
        // owner's tools pass.
        let raise = chain
            .set_role(
                &owner.secret(),
                bob.public(),
                Role::Editor,
                Cut::from([(CHAIN, 3)]),
            )
            .unwrap();
        let raised: Record = bounded::decode(&raise.bytes).unwrap();
        assert!(matches!(&raised.op, Op::SetRole { cut, .. } if cut.is_empty()));
        took(Ok(raise), &mut chain);
        let (remove, epoch1) = chain
            .remove(
                &owner.secret(),
                &epoch0,
                ann.public(),
                Cut::from([(CHAIN, 5)]),
                &binary(),
            )
            .unwrap();
        chain.take(&remove).unwrap();
        admitted(&mut chain, &owner, &epoch1, &cat, Role::Viewer);
        for signed in chain.since(0) {
            copy.take(signed).unwrap();
        }
        for view in [&chain, &copy] {
            // In the chain's order on every copy; Ann, removed, keeps her
            // place.
            assert_eq!(
                view.admitted(),
                [owner.public(), ann.public(), bob.public(), cat.public()]
            );
            judged(view, &owner, [&ann, &bob, &cat]);
        }
        // Epoch 1's key went to the owner and Bob, never to Ann.
        let record = copy.take(&remove).unwrap_err();
        assert!(record.to_string().contains("does not follow"));
        let removal: Record = postcard::from_bytes(&remove.bytes).unwrap();
        let wrapped = |who: &Identity| {
            removal
                .wraps
                .iter()
                .find(|(key, _)| *key == who.public())
                .map(|(_, wrap)| {
                    crypto::unwrap(wrap, PROJECT, 1, who.public(), &who.agreement_secret())
                })
        };
        assert!(wrapped(&ann).is_none());
        let body = vec![1, 2, 3];
        let head = Head {
            chain: CHAIN,
            seq: 2,
            prev: ChangeHash([0; 32]),
            body: Body::commitment(&body),
            origin: None,
        };
        let change = SignedChange {
            head: SignedHead::sign(head, &Signer::from_seed(&[1; 32])),
            body,
        };
        let by = SigningKey::from_bytes(&owner.secret());
        let genesis = chain.genesis().unwrap();
        let bytes = crypto::seal(&epoch1.log(PROJECT), PROJECT, &genesis, 1, &change, &by).unwrap();
        let sealed = Envelope::parse(&bytes).unwrap();
        for who in [&owner, &bob] {
            let key = wrapped(who).unwrap().unwrap();
            assert!(crypto::open(&key.log(PROJECT), &genesis, &sealed, change.hash()).is_some());
        }
        assert!(crypto::open(&epoch0.log(PROJECT), &genesis, &sealed, change.hash()).is_none());
        // A record replayed, reordered or forged is refused.
        let mut fresh = Membership::expecting(PROJECT, owner.public());
        assert!(fresh.take(&add_ann).is_err());
        let mut forged = chain.since(0)[0].clone();
        forged.bytes[20] ^= 1;
        assert!(fresh.take(&forged).is_err());
        fresh.take(&chain.since(0)[0]).unwrap();
        assert!(fresh.take(&add_bob).is_err());
        let mut other = Membership::expecting(PROJECT, ann.public());
        assert!(other.take(&chain.since(0)[0]).is_err());
    }

    #[test]
    fn a_chain_keeps_its_grants_role_and_closing_is_final_on_every_copy() {
        let (owner, ann, bob) = (
            Identity::ephemeral().unwrap(),
            Identity::ephemeral().unwrap(),
            Identity::ephemeral().unwrap(),
        );
        let never = |verdict: Verdict| matches!(verdict, Verdict::Never(_));
        let (mut chain, epoch0) = created(&owner);
        admitted(&mut chain, &owner, &epoch0, &ann, Role::Editor);
        // Ann's chains under grant 2: one the owner saw to its third
        // change, one it never saw; and one under her readmission.
        let (seen, unseen, again) = (ChainId([4; 16]), ChainId([5; 16]), ChainId([6; 16]));
        let known = [
            (seen, ann.public(), 2),
            (unseen, ann.public(), 2),
            (again, ann.public(), 4),
        ];
        let (removal, epoch1) = chain
            .remove(
                &owner.secret(),
                &epoch0,
                ann.public(),
                Cut::from([(seen, 3)]),
                &binary(),
            )
            .unwrap();
        let record: Record = bounded::decode(&removal.bytes).unwrap();
        let expected = BTreeMap::from([(seen, 4), (unseen, 1)]);
        assert_eq!(chain.caused(&record, &known), expected);
        chain.take(&removal).unwrap();
        let readmit = chain
            .readmit(
                &owner.secret(),
                &epoch1,
                &Card::new(&ann, "Ann"),
                Role::Editor,
            )
            .unwrap();
        let record: Record = bounded::decode(&readmit.bytes).unwrap();
        // A readmission closes nothing and reopens nothing.
        assert_eq!(chain.caused(&record, &known), BTreeMap::new());
        chain.take(&readmit).unwrap();
        assert_eq!(chain.grant(ann.public()), Some(4));
        // Bob a viewer, raised: a raise closes nothing and carries no cut.
        admitted(&mut chain, &owner, &epoch1, &bob, Role::Viewer);
        let raised = chain
            .set_role(&owner.secret(), bob.public(), Role::Editor, Cut::new())
            .unwrap();
        chain.take(&raised).unwrap();
        let signer = SigningKey::from_bytes(&owner.secret());
        let with_cut = Op::SetRole {
            member: bob.public(),
            role: Role::Agent,
            cut: Cut::from([(CHAIN, 1)]).try_into().unwrap(),
        };
        assert!(chain.sign(&signer, with_cut, 1, Vec::new()).is_err());
        // Bob lowered: his editor's chain closes past its cut, his
        // viewer's chain writes no more than it did and stays open.
        let (viewed, edited) = (ChainId([7; 16]), ChainId([8; 16]));
        took(
            chain.set_role(
                &owner.secret(),
                bob.public(),
                Role::Viewer,
                Cut::from([(edited, 2)]),
            ),
            &mut chain,
        );
        let mut copy = Membership::expecting(PROJECT, owner.public());
        for signed in chain.since(0) {
            copy.take(signed).unwrap();
        }
        let all = [
            (seen, ann.public(), 2),
            (unseen, ann.public(), 2),
            (again, ann.public(), 4),
            (viewed, bob.public(), 5),
            (edited, bob.public(), 6),
        ];
        for view in [&chain, &copy] {
            let mut closed = expected.clone();
            closed.insert(edited, 3);
            assert_eq!(view.freezes(&all), closed);
            assert_eq!(
                view.judge(ann.public(), seen, 3, 2, Writes::Edit),
                Verdict::Admit
            );
            assert!(never(view.judge(ann.public(), seen, 4, 2, Writes::Edit)));
            assert!(never(view.judge(ann.public(), unseen, 2, 2, Writes::Edit)));
            assert_eq!(
                view.judge(ann.public(), again, 2, 4, Writes::Edit),
                Verdict::Admit
            );
            assert!(never(view.judge(bob.public(), viewed, 2, 5, Writes::Edit)));
            assert_eq!(
                view.judge(bob.public(), viewed, 9, 5, Writes::Talk),
                Verdict::Admit
            );
            assert!(never(view.judge(bob.public(), edited, 3, 6, Writes::Talk)));
        }
    }

    /// A chain `owner` created, then three epochs each started by
    /// removing a viewer added for it: the chain and the four epochs'
    /// keys.
    fn three_epochs(owner: &Identity) -> (Membership, Vec<EpochKey>) {
        let (mut chain, key) = created(owner);
        let mut keys = vec![key];
        for _ in 0..3 {
            let gone = Identity::ephemeral().unwrap();
            let key = keys.last().unwrap().clone();
            admitted(&mut chain, owner, &key, &gone, Role::Viewer);
            let (removal, next) = chain
                .remove(&owner.secret(), &key, gone.public(), Cut::new(), &binary())
                .unwrap();
            chain.take(&removal).unwrap();
            keys.push(next);
        }
        (chain, keys)
    }

    #[test]
    fn a_member_added_at_epoch_3_derives_every_earlier_log_key_and_no_live_key() {
        let (owner, dan) = (
            Identity::ephemeral().unwrap(),
            Identity::ephemeral().unwrap(),
        );
        let (mut chain, keys) = three_epochs(&owner);
        let add = admitted(&mut chain, &owner, &keys[3], &dan, Role::Editor);
        // Dan's copy of the chain, from the records alone, names the same
        // share; of the keys, he is given epoch 3's.
        let mut copy = Membership::expecting(PROJECT, owner.public());
        for signed in chain.since(0) {
            copy.take(signed).unwrap();
        }
        let first = *blake3::hash(&chain.since(0)[0].bytes).as_bytes();
        assert_eq!(
            (copy.genesis(), chain.genesis()),
            (Some(first), Some(first))
        );
        let record: Record = bounded::decode(&add.bytes).unwrap();
        let (_, wrap) = &record.wraps[0];
        let his = crypto::unwrap(wrap, PROJECT, 3, dan.public(), &dan.agreement_secret()).unwrap();
        let derived = copy.history(3, &his, &BTreeMap::new()).unwrap();
        assert_eq!(derived.keys().copied().collect::<Vec<_>>(), [0, 1, 2]);
        for (epoch, subkeys) in &derived {
            assert_eq!(*subkeys, keys[*epoch as usize].subkeys(PROJECT));
        }
        // Holding an earlier epoch's key, the walk checks the link against
        // it.
        let held = BTreeMap::from([(1, keys[1].clone())]);
        assert_eq!(copy.history(3, &his, &held).unwrap(), derived);
        // No epoch key: none derived is one (none makes any epoch's
        // subkeys), and none opens what an epoch seals for presence, chat
        // or the binary.
        let all: Vec<[u8; 32]> = derived
            .values()
            .flat_map(|subkeys| {
                [
                    *subkeys.log(),
                    *subkeys.snapshot(),
                    *subkeys.blobkey(),
                    *subkeys.history(),
                ]
            })
            .collect();
        for key in &keys {
            for bytes in &all {
                assert_ne!(
                    EpochKey::from_bytes(*bytes).subkeys(PROJECT),
                    key.subkeys(PROJECT)
                );
            }
            for purpose in ["presence", "live", "binary"] {
                let sealed = crypto::seal_bare(&key.cipher(PROJECT, purpose), b"here").unwrap();
                for bytes in &all {
                    let cipher = XChaCha20Poly1305::new(&Key::from(*bytes));
                    assert!(crypto::open_bare(&cipher, &sealed).is_none());
                }
            }
        }
        // Given epoch 1's key only, he derives epoch 0's and no later one.
        let from_1 = copy.history(1, &keys[1], &BTreeMap::new()).unwrap();
        assert_eq!(from_1.keys().copied().collect::<Vec<_>>(), [0]);
    }

    #[test]
    fn a_history_link_sealing_other_keys_is_told_to_a_member_holding_the_epoch_before() {
        let (owner, ann) = (
            Identity::ephemeral().unwrap(),
            Identity::ephemeral().unwrap(),
        );
        let (mut chain, epoch0) = created(&owner);
        admitted(&mut chain, &owner, &epoch0, &ann, Role::Viewer);
        let (removal, epoch1) = chain
            .remove(
                &owner.secret(),
                &epoch0,
                ann.public(),
                Cut::new(),
                &binary(),
            )
            .unwrap();
        // The owner's record, its link sealing another key's subkeys.
        let mut record: Record = bounded::decode(&removal.bytes).unwrap();
        let Op::Remove { history, .. } = &mut record.op else {
            panic!("not a removal");
        };
        let other = EpochKey::random().unwrap();
        *history = Exact::from(
            crypto::seal_history(
                &epoch1.subkeys(PROJECT),
                &chain.genesis().unwrap(),
                1,
                &record.prev,
                &other.subkeys(PROJECT),
            )
            .unwrap(),
        );
        let bytes = Bytes::try_from(postcard::to_allocvec(&record).unwrap()).unwrap();
        let wrong = SignedRecord {
            sig: SigningKey::from_bytes(&owner.secret()).sign(&bytes),
            bytes,
        };
        // It is a valid record: a newcomer cannot tell.
        let mut copy = chain.clone();
        copy.take(&wrong).unwrap();
        let derived = copy.history(1, &epoch1, &BTreeMap::new()).unwrap();
        assert_ne!(derived[&0], epoch0.subkeys(PROJECT));
        // A member holding epoch 0's key is told.
        assert!(copy.check_history(1, &epoch1, &epoch0).is_err());
        let held = BTreeMap::from([(0, epoch0.clone())]);
        assert!(copy.history(1, &epoch1, &held).is_err());
        // The owner's own link checks.
        chain.take(&removal).unwrap();
        chain.check_history(1, &epoch1, &epoch0).unwrap();
    }

    /// `record` with `from`, the encoding of one of its fields, replaced by
    /// `to`, signed by `owner`: a record its type could not hold.
    fn forged(record: &Record, from: &[u8], to: &[u8], owner: &Identity) -> SignedRecord {
        let bytes = postcard::to_allocvec(record).unwrap();
        let at = bytes
            .windows(from.len())
            .position(|window| window == from)
            .unwrap();
        let bytes =
            Bytes::try_from([&bytes[..at], to, &bytes[at + from.len()..]].concat()).unwrap();
        SignedRecord {
            sig: SigningKey::from_bytes(&owner.secret()).sign(&bytes),
            bytes,
        }
    }

    /// A cut naming `chains` chains, of group `group`, each to its last
    /// change: the most bytes a cut entry takes.
    fn cut_of(group: usize, chains: usize) -> Cut {
        (0..chains)
            .map(|i| {
                let mut id = [0; 16];
                id[..8].copy_from_slice(&(group as u64).to_le_bytes());
                id[8..].copy_from_slice(&(i as u64).to_le_bytes());
                (ChainId(id), u64::MAX)
            })
            .collect()
    }

    /// Member `n`'s key: one admitted as a store, who holds no key.
    fn store(n: usize) -> PublicKey {
        let mut key = [7; 32];
        key[..8].copy_from_slice(&(n as u64).to_le_bytes());
        PublicKey(key)
    }

    #[test]
    fn records_past_a_bound_are_refused_by_every_copy() {
        let (owner, bob) = (
            Identity::ephemeral().unwrap(),
            Identity::ephemeral().unwrap(),
        );
        let (mut chain, key) = created(&owner);
        let length = |bytes: usize| postcard::to_allocvec(&vec![9u8; bytes]).unwrap();
        let refused =
            |chain: &Membership, signed: &SignedRecord| chain.clone().take(signed).is_err();
        // A wrap of one byte more or less than its length.
        let add = chain
            .add(
                &owner.secret(),
                &key,
                bob.public(),
                bob.agreement(),
                Role::Editor,
            )
            .unwrap();
        let record: Record = bounded::decode(&add.bytes).unwrap();
        let wrap = postcard::to_allocvec(&record.wraps[0].1).unwrap();
        assert_eq!(wrap.len(), 1 + WRAP);
        for bytes in [WRAP - 1, WRAP + 1] {
            assert!(refused(
                &chain,
                &forged(&record, &wrap, &length(bytes), &owner)
            ));
        }
        chain.take(&add).unwrap();
        // A cut of one chain past its bound.
        let set = chain
            .set_role(
                &owner.secret(),
                bob.public(),
                Role::Viewer,
                cut_of(0, MAX_CUT),
            )
            .unwrap();
        let record: Record = bounded::decode(&set.bytes).unwrap();
        let cut = postcard::to_allocvec(&cut_of(0, MAX_CUT)).unwrap();
        let over = postcard::to_allocvec(&cut_of(0, MAX_CUT + 1)).unwrap();
        assert!(refused(&chain, &forged(&record, &cut, &over, &owner)));
        chain.take(&set).unwrap();
        // A history link of one byte more or less than its length.
        let (removal, epoch1) = chain
            .remove(&owner.secret(), &key, bob.public(), Cut::new(), &binary())
            .unwrap();
        let record: Record = bounded::decode(&removal.bytes).unwrap();
        let Op::Remove { history, .. } = &record.op else {
            panic!("not a removal");
        };
        let link = postcard::to_allocvec(history).unwrap();
        assert_eq!(link.len(), 2 + HISTORY);
        for bytes in [HISTORY - 1, HISTORY + 1] {
            assert!(refused(
                &chain,
                &forged(&record, &link, &length(bytes), &owner)
            ));
        }
        chain.take(&removal).unwrap();
        // A record of one byte past its bound does not read.
        let sig = Signature::from_bytes(&[0; 64]);
        for (bytes, reads) in [(MAX_RECORD, true), (MAX_RECORD + 1, false)] {
            let signed = postcard::to_allocvec(&(vec![0u8; bytes], sig)).unwrap();
            assert_eq!(bounded::decode::<SignedRecord>(&signed).is_ok(), reads);
        }
        // At most 256 members not removed, the owner among them: one more
        // is refused, and admitted once another is removed.
        for n in 0..MAX_MEMBERS - 1 {
            took(
                chain.add(&owner.secret(), &epoch1, store(n), [0; 32], Role::Store),
                &mut chain,
            );
        }
        let one_more = |chain: &Membership| {
            chain.add(
                &owner.secret(),
                &epoch1,
                store(MAX_MEMBERS),
                [0; 32],
                Role::Store,
            )
        };
        assert!(one_more(&chain).is_err());
        let (removal, _) = chain
            .remove(&owner.secret(), &epoch1, store(0), Cut::new(), &binary())
            .unwrap();
        chain.take(&removal).unwrap();
        took(one_more(&chain), &mut chain);
    }

    #[test]
    fn removals_fit_where_other_records_no_longer_do_and_none_past_32_mib() {
        let owner = Identity::ephemeral().unwrap();
        let (mut chain, mut key) = created(&owner);
        let members = MAX_MEMBERS - 2;
        for n in 0..members {
            took(
                chain.add(&owner.secret(), &key, store(n), [0; 32], Role::Store),
                &mut chain,
            );
        }
        // The largest records: a lowering cutting every chain it may name
        // (only a lowering carries a cut), each after a raise.
        let editor = Identity::ephemeral().unwrap();
        admitted(&mut chain, &owner, &key, &editor, Role::Editor);
        let big = |n: usize| cut_of(n, MAX_CUT);
        let mut n = 0;
        let role = |chain: &Membership, role: Role, cut: Cut| {
            chain.set_role(&owner.secret(), editor.public(), role, cut)
        };
        while let Ok(lower) = role(&chain, Role::Viewer, big(n)) {
            chain.take(&lower).unwrap();
            n += 1;
            let Ok(raise) = role(&chain, Role::Editor, Cut::new()) else {
                break;
            };
            chain.take(&raise).unwrap();
        }
        let largest = chain
            .since(0)
            .iter()
            .map(|signed| signed.bytes.len() + 64)
            .max()
            .unwrap();
        assert!(largest > 100 << 10 && largest <= MAX_RECORD + 64);
        assert!(chain.bytes() <= MAX_CHAIN && chain.bytes() + largest > MAX_CHAIN);
        // Past 8 MiB: a removal still fits, a smaller record of another
        // kind does not.
        let mut removed = 0;
        loop {
            let removal = chain.remove(&owner.secret(), &key, store(removed), big(n), &binary());
            let Ok((signed, next)) = removal else {
                break;
            };
            chain.take(&signed).unwrap();
            (key, removed, n) = (next, removed + 1, n + 1);
            if chain.bytes() > MAX_CHAIN {
                let add = chain.add(&owner.secret(), &key, store(members), [0; 32], Role::Store);
                assert!(add.is_err());
            }
        }
        assert!(removed < members, "members left to remove");
        assert!(chain.crowded());
        assert!(
            chain.bytes() <= MAX_CHAIN_REMOVING && chain.bytes() + largest > MAX_CHAIN_REMOVING
        );
        // Every copy agrees, record by record.
        let mut copy = Membership::expecting(PROJECT, owner.public());
        for signed in chain.since(0) {
            copy.take(signed).unwrap();
        }
        assert_eq!(copy.bytes(), chain.bytes());
    }

    #[test]
    fn two_records_conflict_only_if_their_one_signer_signed_both_after_the_same_records() {
        let [owner, ann, bob, cat] = [(); 4].map(|()| Identity::ephemeral().unwrap());
        let (mut chain, key) = created(&owner);
        admitted(&mut chain, &owner, &key, &ann, Role::Editor);
        let branch = chain.clone();
        let held = admitted(&mut chain, &owner, &key, &bob, Role::Viewer);
        // The owner signed another record 3 after the same two.
        let theirs = branch
            .add(
                &owner.secret(),
                &key,
                cat.public(),
                cat.agreement(),
                Role::Viewer,
            )
            .unwrap();
        assert!(chain.conflicts(3, &theirs));
        // The record held, or one said to be at another number: none.
        assert!(!chain.conflicts(3, &held));
        assert!(!chain.conflicts(2, &theirs));
        // Its bytes signed by another key: none.
        let forged = |by: &Identity, bytes: &Bytes<MAX_RECORD>| SignedRecord {
            sig: SigningKey::from_bytes(&by.secret()).sign(bytes),
            bytes: bytes.clone(),
        };
        assert!(!chain.conflicts(3, &forged(&ann, &theirs.bytes)));
        // The owner's record 3 of another share: none; nor its first.
        let (mut elsewhere, other) = created(&owner);
        admitted(&mut elsewhere, &owner, &other, &cat, Role::Editor);
        let unrelated = elsewhere
            .add(
                &owner.secret(),
                &other,
                bob.public(),
                bob.agreement(),
                Role::Viewer,
            )
            .unwrap();
        assert!(!chain.conflicts(3, &unrelated));
        assert!(!chain.conflicts(1, elsewhere.record(1).unwrap()));
        // Past a transfer, whoever signed at that number: the new owner,
        // not the one before.
        took(chain.transfer(&owner.secret(), ann.public()), &mut chain);
        let branch = chain.clone();
        took(
            chain.add(
                &ann.secret(),
                &key,
                cat.public(),
                cat.agreement(),
                Role::Viewer,
            ),
            &mut chain,
        );
        let theirs = branch
            .set_role(&ann.secret(), bob.public(), Role::Editor, Cut::new())
            .unwrap();
        assert_eq!(chain.signer_at(5), Some(ann.public()));
        assert!(chain.conflicts(5, &theirs));
        assert!(!chain.conflicts(5, &forged(&owner, &theirs.bytes)));
    }

    #[test]
    fn a_record_names_no_project() {
        let owner = Identity::ephemeral().unwrap();
        let (chain, _) = created(&owner);
        let first = chain.record(1).unwrap();
        assert!(
            !first
                .bytes
                .windows(PROJECT.0.len())
                .any(|bytes| bytes == PROJECT.0)
        );
        // Its routing id is the locator's alone: a chain expected under
        // another takes it all the same.
        let mut elsewhere = Membership::expecting(ProjectId([9; 16]), owner.public());
        elsewhere.take(first).unwrap();
        assert_eq!(elsewhere.genesis(), chain.genesis());
    }
}
