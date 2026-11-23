//! Model peers for the sync machine: an in-memory [`Storage`] whose rules
//! are the design's in small (§4, §5, §7), with real heads, signatures and
//! fork proofs, and a network of peers whose messages, pages and timers a
//! schedule drives.
//!
//! What the model leaves out: sealing (a body travels as plain bytes with
//! an all-zero tag), membership signatures (records are owner-made and
//! trusted), projections (the admitted set is the projection compared).

#![allow(
    dead_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::wildcard_enum_match_arm,
    reason = "a test model: each test uses part of it, and fails loudly"
)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use binbun_session::journal::{
    Body, Cause, ChainId, ChainOrigin, ChangeHash, ChangeId, ForkProof, Head, ProjectId, PublicKey,
    SignedHead, Signer, Tip, Under, Why,
};
use binbun_sync::envelope::{Parts, TAG};
use binbun_sync::machine::Told;
use binbun_sync::wire::{Hash, Mark};
use binbun_sync::{
    Admission, Closed, Counting, Effect, Envelope, Event, ForkTaken, Job, LinkId, Local, Machine,
    Output, Phase, Records, RecordsRefused, Send, Storage, Sync, TIPS_SCAN, Taken, Walk,
};
use serde::{Deserialize, Serialize};

/// The share's id in every envelope.
pub const SHARE: ProjectId = ProjectId([0x5a; 16]);

/// The home binary every peer is on unless told otherwise.
pub const BINARY: [u8; 32] = [0xb1; 32];

/// Changes the held cache keeps.
pub const MAX_HELD: usize = 8;

/// A membership record's operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    /// The first record: the owner, and the prefixes from before the
    /// share it lists.
    Create {
        /// The owner.
        owner: [u8; 32],
        /// `(chain, through, hash)`.
        before: Vec<([u8; 16], u64, [u8; 32])>,
    },
    /// A member added (or readmitted), as an editor or a viewer: a grant,
    /// carrying no cut.
    Add {
        /// The key.
        key: [u8; 32],
        /// Whether they write.
        editor: bool,
    },
    /// A member's role changed: a grant; a lowering carries the cut of
    /// the chains it closes.
    Role {
        /// The key.
        key: [u8; 32],
        /// Whether they write.
        editor: bool,
        /// Each chain of theirs the owner saw, and its last change there.
        cuts: Vec<([u8; 16], u64)>,
    },
    /// A member removed.
    Remove {
        /// The key.
        key: [u8; 32],
        /// Each chain of theirs the owner saw, and its last change there.
        cuts: Vec<([u8; 16], u64)>,
    },
}

/// A membership record as the model writes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Its number, from 1.
    pub seq: u64,
    /// The hash of the record before.
    pub prev: [u8; 32],
    /// What it does.
    pub op: Op,
}

impl Record {
    /// Its bytes.
    pub fn bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }
}

/// A record's hash.
pub fn record_hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// A model body: a start's binding, or an edit's dependencies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelBody {
    /// A start: the share and the grant it is written under (none: a
    /// chain from before the share) and the binary.
    Start {
        /// The share's genesis and the chain's grant.
        share: Option<Under>,
        /// The binary.
        binary: [u8; 32],
        /// Makes two starts of one chain differ.
        blind: u8,
    },
    /// An edit.
    Edit {
        /// Changes it names.
        deps: Vec<([u8; 16], u64)>,
        /// Malformed: refused for good.
        never: bool,
        /// Makes two edits at one number differ.
        blind: u8,
    },
}

/// One admitted chain.
#[derive(Clone, Debug)]
pub struct Chain {
    /// What makes its id.
    pub origin: ChainOrigin,
    /// The membership record its start names as its grant (none: a chain
    /// from before the share).
    pub grant: Option<u64>,
    /// Its admitted changes from the start, each head and envelope.
    pub changes: Vec<(SignedHead, Vec<u8>)>,
    /// The first number not kept, if frozen.
    pub frozen: Option<u64>,
    /// Its fork proof.
    pub proof: Option<ForkProof>,
    /// The head refused for good, if any.
    pub refused: Option<SignedHead>,
}

impl Chain {
    /// A chain from before the share, held with `changes`.
    pub fn prior(origin: ChainOrigin, changes: Vec<(SignedHead, Vec<u8>)>) -> Self {
        Self {
            origin,
            grant: None,
            changes,
            frozen: None,
            proof: None,
            refused: None,
        }
    }

    /// The changes in effect below `limit` (the first number not kept, by
    /// any cause): from the start, which only a fork at 1 takes.
    fn effective(&self, limit: Option<u64>) -> &[(SignedHead, Vec<u8>)] {
        let mut end = limit
            .map_or(self.changes.len(), |from| {
                usize::try_from(from.saturating_sub(1)).unwrap_or(usize::MAX)
            })
            .min(self.changes.len());
        if self.proof.is_none_or(|proof| proof.place() > 1) {
            end = end.max(self.changes.len().min(1));
        }
        &self.changes[..end]
    }
}

/// A peer's durable state and the rules it judges by.
#[derive(Clone, Debug)]
pub struct Model {
    /// Its key.
    pub key: PublicKey,
    /// Its membership records as bytes.
    pub records: Vec<Vec<u8>>,
    /// Chains known here.
    pub chains: BTreeMap<ChainId, Chain>,
    /// Envelopes held for the change they wait for.
    pub held: BTreeMap<ChangeId, Vec<(PublicKey, Vec<u8>)>>,
    /// Epochs whose keys are here.
    pub keys: BTreeSet<u32>,
    /// The binary this peer's session is on.
    pub binary: [u8; 32],
    /// Walks of listed prefixes: lowest checked, its prev, the hashes.
    pub walks: BTreeMap<ChainId, (u64, ChangeHash, BTreeMap<u64, ChangeHash>)>,
    /// The most hashes the walks may hold at once, if any are refused.
    pub walk_ceiling: Option<usize>,
    /// Whether the share is in recovery.
    pub recovering: bool,
    /// Events not yet read.
    pub events: Vec<Event>,
    /// Envelopes of changes this peer made but did not admit (pending).
    pub pending: Vec<Vec<u8>>,
    /// Changes admitted, as ever told to the harness: for the authority
    /// property, the admitted set at each step.
    pub admitted_log: Vec<ChangeId>,
    /// Changes applied past their chain's limit: each a breach of P2.
    pub violations: Vec<ChangeId>,
    /// The membership its records say, as of which records.
    cache: RefCell<Option<(Of, Members)>>,
}

/// Which records a membership was computed from: their count and the
/// last one's hash.
type Of = (usize, Option<[u8; 32]>);

/// A role in the model's membership, by what it may write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Reads.
    Viewer,
    /// Writes.
    Editor,
}

/// A record that set a key's entry (a grant) or removed it.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Its number.
    pub seq: u64,
    /// The key.
    pub key: PublicKey,
    /// The role it left (none: removed).
    pub role: Option<Role>,
    /// The cut it carries: chain, the last change that stands.
    pub cuts: BTreeMap<ChainId, u64>,
}

/// The membership a chain of records says, judged by grants (sync §4.3):
/// a chain has the role of the record its start names, for good; the
/// first later record that leaves its author able to write less than
/// that closes it, at the change its cut names or, the chain not named,
/// at its start; nothing reopens it.
#[derive(Clone, Debug, Default)]
pub struct Members {
    /// Members now, with their roles.
    pub now: BTreeMap<PublicKey, Role>,
    /// Everyone ever named.
    pub ever: BTreeSet<PublicKey>,
    /// The records that set or removed an entry, in order.
    pub entries: Vec<Entry>,
    /// The listed prefixes.
    pub before: BTreeMap<ChainId, (u64, ChangeHash)>,
}

impl Members {
    /// The role record `grant` gave `author`, if it set `author`'s entry.
    pub fn grant(&self, grant: u64, author: PublicKey) -> Option<Role> {
        self.entries
            .iter()
            .find(|entry| entry.seq == grant)
            .filter(|entry| entry.key == author)
            .and_then(|entry| entry.role)
    }

    /// The latest record that set `key`'s entry.
    pub fn grant_of(&self, key: PublicKey) -> Option<u64> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.key == key && entry.role.is_some())
            .map(|entry| entry.seq)
    }

    /// Where `chain`, of `author` under `grant`, is closed, if it is: the
    /// first number not kept, and whether the closing record's cut names
    /// the chain (if not, it is closed at its start).
    pub fn closed(&self, chain: ChainId, grant: u64, author: PublicKey) -> Option<(u64, bool)> {
        let role = self.grant(grant, author)?;
        let closing = self
            .entries
            .iter()
            .find(|entry| entry.seq > grant && entry.key == author && entry.role < Some(role))?;
        Some(match closing.cuts.get(&chain) {
            Some(last) => (last.saturating_add(1).max(2), true),
            None => (2, false),
        })
    }

    /// Takes record `seq`, setting `key` to `role` (none: removed).
    fn set(&mut self, seq: u64, key: PublicKey, role: Option<Role>, cuts: &[([u8; 16], u64)]) {
        match role {
            Some(role) => {
                self.now.insert(key, role);
            }
            None => {
                self.now.remove(&key);
            }
        }
        self.ever.insert(key);
        self.entries.push(Entry {
            seq,
            key,
            role,
            cuts: cuts
                .iter()
                .map(|(chain, last)| (ChainId(*chain), *last))
                .collect(),
        });
    }
}

/// The membership `records` say.
pub fn members(records: &[Vec<u8>]) -> Members {
    let mut members = Members::default();
    for bytes in records {
        let record: Record = postcard::from_bytes(bytes).unwrap();
        match record.op {
            Op::Create { owner, before } => {
                members.set(record.seq, PublicKey(owner), Some(Role::Editor), &[]);
                for (chain, through, hash) in before {
                    members
                        .before
                        .insert(ChainId(chain), (through, ChangeHash(hash)));
                }
            }
            Op::Add { key, editor } => {
                let role = if editor { Role::Editor } else { Role::Viewer };
                members.set(record.seq, PublicKey(key), Some(role), &[]);
            }
            Op::Role { key, editor, cuts } => {
                let role = if editor { Role::Editor } else { Role::Viewer };
                members.set(record.seq, PublicKey(key), Some(role), &cuts);
            }
            Op::Remove { key, cuts } => members.set(record.seq, PublicKey(key), None, &cuts),
        }
    }
    members
}

/// The envelope of `head` with `body`, in epoch 0.
pub fn seal(head: SignedHead, body: &ModelBody) -> Vec<u8> {
    seal_in(head, body, 0)
}

/// The envelope of `head` with `body`, sealed in `epoch`.
pub fn seal_in(head: SignedHead, body: &ModelBody, epoch: u32) -> Vec<u8> {
    let bytes = postcard::to_allocvec(body).unwrap();
    let mut ciphertext = bytes;
    ciphertext.extend_from_slice(&[0; TAG]);
    Envelope::write(&Parts {
        project: SHARE,
        signed_head: &head.bytes(),
        epoch,
        nonce: &[0; 24],
        ciphertext: &ciphertext,
        sealer: &[0; 32],
        seal_sig: &[0; 64],
    })
    .unwrap()
}

/// The body an envelope carries, if it opens and matches its head.
fn open(envelope: &Envelope<'_>, head: &Head) -> Option<ModelBody> {
    let ciphertext = envelope.ciphertext();
    let body = &ciphertext[..ciphertext.len() - TAG];
    if Body::commitment(body) != head.body {
        return None;
    }
    postcard::from_bytes(body).ok()
}

/// The admission of a head `theirs` that forks with `mine`.
fn fork(origin: ChainOrigin, mine: SignedHead, theirs: SignedHead) -> Admission {
    ForkProof::new(origin, mine, theirs)
        .map_or(Admission::Invalid, |proof| Admission::Fork(Box::new(proof)))
}

/// A head of `chain` at `seq` after `prev`, of `body`, signed.
pub fn sign(
    signer: &Signer,
    origin: ChainOrigin,
    seq: u64,
    prev: ChangeHash,
    body: &ModelBody,
) -> SignedHead {
    let bytes = postcard::to_allocvec(body).unwrap();
    let head = Head {
        chain: origin.chain(),
        seq,
        prev,
        body: Body::commitment(&bytes),
        origin: (seq == 1).then_some(origin),
    };
    SignedHead::sign(head, signer)
}

impl Model {
    /// A peer of `key` on the home binary, with the records given.
    pub fn new(key: PublicKey, records: Vec<Vec<u8>>) -> Self {
        Self {
            key,
            records,
            chains: BTreeMap::new(),
            held: BTreeMap::new(),
            keys: BTreeSet::from([0]),
            binary: BINARY,
            walks: BTreeMap::new(),
            walk_ceiling: None,
            recovering: false,
            events: Vec::new(),
            pending: Vec::new(),
            admitted_log: Vec::new(),
            violations: Vec::new(),
            cache: RefCell::new(None),
        }
    }

    /// The membership its records say.
    pub fn members(&self) -> Members {
        let key = (
            self.records.len(),
            self.records.last().map(|r| record_hash(r)),
        );
        let mut cache = self.cache.borrow_mut();
        match &*cache {
            Some((at, members)) if *at == key => members.clone(),
            Some(_) | None => {
                let members = members(&self.records);
                *cache = Some((key, members.clone()));
                members
            }
        }
    }

    /// The first number of `chain` not kept, by any cause (a fork, a
    /// `Never`, a record that closed it). No record closes a listed
    /// prefix: it is the first record's, and names no grant.
    pub fn limit(&self, chain: ChainId) -> Option<u64> {
        let c = self.chains.get(&chain)?;
        let cut = c.grant.and_then(|grant| {
            self.members()
                .closed(chain, grant, c.origin.author)
                .map(|(from, _)| from)
        });
        match (c.frozen, cut) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// `chain`'s changes in effect.
    fn effective(&self, chain: ChainId) -> &[(SignedHead, Vec<u8>)] {
        let limit = self.limit(chain);
        self.chains.get(&chain).map_or(&[], |c| c.effective(limit))
    }

    /// Every known chain's limit.
    fn limits(&self) -> BTreeMap<ChainId, Option<u64>> {
        self.chains
            .keys()
            .map(|chain| (*chain, self.limit(*chain)))
            .collect()
    }

    /// The genesis.
    pub fn share(&self) -> [u8; 32] {
        self.records.first().map_or([0; 32], |r| record_hash(r))
    }

    /// Admitted changes: chain to the hashes in effect.
    pub fn admitted(&self) -> BTreeMap<ChainId, Vec<ChangeHash>> {
        self.chains
            .keys()
            .map(|chain| {
                let hashes = self
                    .effective(*chain)
                    .iter()
                    .map(|(h, _)| h.hash())
                    .collect();
                (*chain, hashes)
            })
            .collect()
    }

    /// Whether `change` is admitted here (in effect).
    pub fn holds(&self, change: ChangeId) -> bool {
        let effective = self.effective(change.chain).len();
        usize::try_from(change.seq).is_ok_and(|seq| seq >= 1 && seq <= effective)
    }

    /// Whether `change` is dead: its chain frozen at or before it.
    fn dead(&self, change: ChangeId) -> bool {
        self.limit(change.chain)
            .is_some_and(|from| from <= change.seq)
    }

    /// Freezes `chain` from `from` (a fork, a `Never`; lower only),
    /// durably, telling it.
    pub fn freeze(&mut self, chain: ChainId, from: u64) {
        let before = self.limits();
        let Some(c) = self.chains.get_mut(&chain) else {
            return;
        };
        if c.frozen.is_some_and(|f| f <= from) {
            return;
        }
        c.frozen = Some(from);
        self.limits_lowered(&before);
    }

    /// Tells each chain whose limit went down since `before`, and
    /// releases what waited for a change now dead.
    fn limits_lowered(&mut self, before: &BTreeMap<ChainId, Option<u64>>) {
        for (chain, after) in self.limits() {
            let Some(from) = after else {
                continue;
            };
            if before
                .get(&chain)
                .copied()
                .flatten()
                .is_some_and(|was| was <= from)
            {
                continue;
            }
            self.events.push(Event::Frozen { chain, from });
            let dead: Vec<ChangeId> = self
                .held
                .keys()
                .filter(|w| w.chain == chain && w.seq >= from)
                .copied()
                .collect();
            for waited in dead {
                self.release(waited);
            }
        }
    }

    /// Re-judges what waited for `change`.
    fn release(&mut self, change: ChangeId) {
        for (from, envelope) in self.held.remove(&change).unwrap_or_default() {
            if let Some(parsed) = Envelope::parse(&envelope) {
                self.admit(from, &parsed);
            }
        }
    }

    fn apply(&mut self, chain: ChainId, head: SignedHead, envelope: Vec<u8>) {
        let id = head.id();
        let hash = head.hash();
        if self.limit(chain).is_some_and(|from| id.seq >= from) {
            // P2: nothing past a cut (or a freeze) is ever admitted.
            self.violations.push(id);
        }
        if let Some(c) = self.chains.get_mut(&chain) {
            c.changes.push((head, envelope));
        }
        self.admitted_log.push(id);
        self.events.push(Event::Applied { change: id, hash });
        self.release(id);
    }

    /// Takes this peer's own change, judged as any.
    pub fn commit(&mut self, envelope: Vec<u8>) -> Admission {
        let parsed = Envelope::parse(&envelope).unwrap();
        let key = self.key;
        let admission = self.admit(key, &parsed);
        if !matches!(admission, Admission::Applied | Admission::Same) {
            self.pending.push(envelope);
        }
        admission
    }

    /// Drops the held cache (P5).
    pub fn drop_held(&mut self) {
        self.held.clear();
    }

    /// What survives a restart (everything durable; held changes and
    /// unread events do not).
    pub fn restart(&mut self) {
        self.held.clear();
        self.events.clear();
    }

    /// Takes records made here (the owner's).
    pub fn take_own(&mut self, record: &[u8]) -> Taken {
        let after = self.records.len() as u64;
        let (taken, refused) = self.take_records(after, &[record]);
        refused.unwrap();
        taken
    }

    /// [`Storage::take_records`]: each record taken, and counted in
    /// `taken`, before the next is looked at; the first that fails stops
    /// the page.
    fn take_each(
        &mut self,
        after: u64,
        records: &[&[u8]],
        taken: &mut Taken,
    ) -> Result<(), RecordsRefused> {
        for (i, bytes) in records.iter().enumerate() {
            let seq = after + 1 + i as u64;
            let record: Record =
                postcard::from_bytes(bytes).map_err(|_| RecordsRefused::Invalid)?;
            if record.seq != seq {
                return Err(RecordsRefused::Invalid);
            }
            match self.record_hash(seq) {
                Some(hash) if hash == record_hash(bytes) => continue,
                Some(_) => return Err(RecordsRefused::Mismatch),
                None => {}
            }
            if self.record_hash(seq - 1) != Some(record.prev)
                || seq != self.records.len() as u64 + 1
            {
                return Err(RecordsRefused::Mismatch);
            }
            self.records.push(bytes.to_vec());
            taken.records += 1;
        }
        Ok(())
    }
}

impl Storage for Model {
    fn genesis(&self) -> Hash {
        self.share()
    }

    fn membership(&self) -> Mark {
        let seq = self.records.len() as u64;
        (seq, self.records.last().map_or([0; 32], |r| record_hash(r)))
    }

    fn record_hash(&self, seq: u64) -> Option<Hash> {
        if seq == 0 {
            return Some([0; 32]);
        }
        let index = usize::try_from(seq - 1).ok()?;
        self.records.get(index).map(|r| record_hash(r))
    }

    fn is_member(&self, key: PublicKey) -> bool {
        self.members().now.contains_key(&key)
    }

    fn can_ready(&self, remote: PublicKey) -> bool {
        let members = self.members();
        members.now.contains_key(&remote)
            && members.now.contains_key(&self.key)
            && self.binary == BINARY
    }

    fn records_after(&self, after: u64, at: Hash) -> Records {
        if self.record_hash(after).is_some_and(|hash| hash != at) {
            let index = usize::try_from(after - 1).unwrap();
            return Records::Diverged(self.records[index].clone());
        }
        let start = usize::try_from(after).unwrap().min(self.records.len());
        let records: Vec<Vec<u8>> = self.records[start..].iter().take(2).cloned().collect();
        let more = start + records.len() < self.records.len();
        Records::Page { records, more }
    }

    fn take_records(
        &mut self,
        after: u64,
        records: &[&[u8]],
    ) -> (Taken, Result<(), RecordsRefused>) {
        let mut taken = Taken::default();
        let before = self.limits();
        let refused = self.take_each(after, records, &mut taken);
        self.limits_lowered(&before);
        (taken, refused)
    }

    fn recovering(&self) -> bool {
        self.recovering
    }

    fn listed(&self, chain: ChainId) -> Option<(u64, ChangeHash)> {
        self.members().before.get(&chain).copied()
    }

    fn local(&self) -> PublicKey {
        self.key
    }

    fn tip(&self, chain: ChainId) -> Option<Tip> {
        let c = self.chains.get(&chain)?;
        let effective = self.effective(chain);
        Some(Tip {
            chain,
            project: c.origin.project,
            seq: effective.len() as u64,
            hash: effective.last().map_or(ChangeHash::ZERO, |(h, _)| h.hash()),
            fork: c.proof.map_or(0, |p| p.place()),
        })
    }

    fn tips_after(
        &self,
        after: Option<ChainId>,
        project: Option<ProjectId>,
        most: usize,
    ) -> (Vec<Tip>, Option<ChainId>) {
        let mut chains = self
            .chains
            .keys()
            .filter(|chain| after.is_none_or(|after| **chain > after))
            .peekable();
        let (mut tips, mut last) = (Vec::new(), None);
        for _ in 0..TIPS_SCAN {
            if tips.len() >= most {
                break;
            }
            let Some(&chain) = chains.next() else {
                break;
            };
            last = Some(chain);
            tips.extend(
                self.tip(chain)
                    .filter(|tip| project.is_none_or(|p| tip.project == p)),
            );
        }
        (tips, chains.peek().and(last))
    }

    fn head_at(&self, chain: ChainId, seq: u64) -> Option<SignedHead> {
        let c = self.chains.get(&chain)?;
        if seq == 1 {
            return c.changes.first().map(|(h, _)| *h);
        }
        let index = usize::try_from(seq.checked_sub(1)?).ok()?;
        self.effective(chain).get(index).map(|(h, _)| *h)
    }

    fn author(&self, chain: ChainId) -> Option<PublicKey> {
        self.chains.get(&chain).map(|c| c.origin.author)
    }

    fn origin(&self, chain: ChainId) -> Option<ProjectId> {
        self.chains.get(&chain).map(|c| c.origin.project)
    }

    fn changes_after(
        &mut self,
        chain: ChainId,
        after: u64,
        most: usize,
        room: usize,
    ) -> (Vec<Vec<u8>>, bool) {
        let Some(c) = self.chains.get(&chain) else {
            return (Vec::new(), false);
        };
        let effective = self.effective(chain);
        let mut list: Vec<&Vec<u8>> = Vec::new();
        if after == 0 && effective.is_empty() {
            // The start, kept whatever is frozen after it.
            if let Some((_, envelope)) = c.changes.first() {
                list.push(envelope);
            }
        }
        let start = usize::try_from(after).unwrap_or(usize::MAX);
        list.extend(effective.iter().skip(start).map(|(_, e)| e));
        let mut out = Vec::new();
        let mut bytes = 0;
        for envelope in &list {
            if out.len() >= most || (!out.is_empty() && bytes + envelope.len() > room) {
                break;
            }
            bytes += envelope.len();
            out.push((*envelope).clone());
        }
        let more = out.len() < list.len();
        (out, more)
    }

    fn evidence(&self, chain: ChainId) -> Option<ForkProof> {
        self.chains.get(&chain)?.proof
    }

    fn frozen(&self, chain: ChainId) -> Option<u64> {
        self.limit(chain)
    }

    fn admit(&mut self, from: PublicKey, envelope: &Envelope<'_>) -> Admission {
        let Ok(signed) = SignedHead::parse(envelope.signed_head()) else {
            return Admission::Invalid;
        };
        let head = signed.head;
        let chain = head.chain;
        let Some(known) = self.chains.get(&chain) else {
            return self.admit_start(signed, envelope);
        };
        let origin = known.origin;
        let grant = known.grant;
        if !signed.verify(origin.author) {
            return Admission::Invalid;
        }
        let listed = self.listed(chain);
        // Another head at a listed number is not of the share: no fork.
        let other = |admission: Admission| match (&admission, listed) {
            (Admission::Fork(_), Some((through, _))) if head.seq <= through => {
                Admission::TurnedAway
            }
            _ => admission,
        };
        let first = known.changes.first().map(|(h, _)| *h);
        if head.seq == 1 {
            return other(match first {
                Some(mine) if mine.hash() == signed.hash() => Admission::Same,
                Some(mine) => fork(origin, mine, signed),
                None => Admission::Invalid,
            });
        }
        if self.limit(chain).is_some_and(|f| head.seq >= f) {
            return Admission::Frozen;
        }
        let tip = self.tip(chain).unwrap();
        if head.seq <= tip.seq {
            let mine = self.head_at(chain, head.seq).unwrap();
            return other(if mine.hash() == signed.hash() {
                Admission::Same
            } else {
                fork(origin, mine, signed)
            });
        }
        if head.seq > tip.seq + 1 {
            return Admission::Same;
        }
        // A listed change is taken only on the branch the walk checked,
        // at every number, before its body is opened.
        if let Some((through, _)) = listed
            && (head.seq > through || self.walk_hash(chain, head.seq) != Some(signed.hash()))
        {
            return Admission::TurnedAway;
        }
        if head.prev != tip.hash {
            let mine = self.head_at(chain, tip.seq).unwrap();
            return other(fork(origin, mine, signed));
        }
        let Some(body) = self.open(envelope, &head) else {
            return Admission::Declined;
        };
        let ModelBody::Edit { deps, never, .. } = body else {
            self.refuse(chain, head.seq, signed);
            return Admission::Never {
                why: Why::new("a start past number 1"),
            };
        };
        if never {
            self.refuse(chain, head.seq, signed);
            return Admission::Never {
                why: Why::new("malformed"),
            };
        }
        // The chain's role is its grant's, for good (a listed change is
        // taken on the first record, and names no grant).
        if let Some(grant) = grant
            && self.members().grant(grant, origin.author) != Some(Role::Editor)
        {
            self.refuse(chain, head.seq, signed);
            return Admission::Never {
                why: Why::new("an edit its grant's role may not write"),
            };
        }
        for (dep_chain, dep_seq) in deps {
            let dep = ChangeId {
                chain: ChainId(dep_chain),
                seq: dep_seq,
            };
            if !self.holds(dep) && !self.dead(dep) {
                let count: usize = self.held.values().map(Vec::len).sum();
                if count < MAX_HELD {
                    self.held
                        .entry(dep)
                        .or_default()
                        .push((from, envelope.bytes().to_vec()));
                }
                return Admission::Stopped {
                    cause: Cause::Change(dep),
                    head: Box::new(signed),
                };
            }
        }
        self.apply(chain, signed, envelope.bytes().to_vec());
        Admission::Applied
    }

    fn verify(&self, chain: ChainId, head: &SignedHead) -> bool {
        self.chains.get(&chain).is_some_and(|c| {
            head.head.chain == chain && head.head.well_formed() && head.verify(c.origin.author)
        })
    }

    fn prove(&self, theirs: &SignedHead) -> Option<ForkProof> {
        let chain = theirs.head.chain;
        if self.listed(chain).is_some() {
            return None;
        }
        let c = self.chains.get(&chain)?;
        if !self.verify(chain, theirs) {
            return None;
        }
        if let Some(mine) = self.head_at(chain, theirs.head.seq)
            && mine.hash() != theirs.hash()
        {
            return ForkProof::new(c.origin, mine, *theirs);
        }
        let before = self.head_at(chain, theirs.head.seq.checked_sub(1)?)?;
        (theirs.head.prev != before.hash())
            .then(|| ForkProof::new(c.origin, before, *theirs))
            .flatten()
    }

    fn prove_pair(&self, stopped: &SignedHead, theirs: &SignedHead) -> Option<ForkProof> {
        let chain = stopped.head.chain;
        if self.listed(chain).is_some() || !self.verify(chain, theirs) {
            return None;
        }
        ForkProof::new(self.chains.get(&chain)?.origin, *stopped, *theirs)
    }

    fn take_fork(&mut self, proof: &ForkProof) -> ForkTaken {
        let chain = proof.chain();
        if self.members().before.contains_key(&chain) {
            return ForkTaken::Unknown;
        }
        let Some(c) = self.chains.get_mut(&chain) else {
            return ForkTaken::Unknown;
        };
        if c.origin != proof.origin {
            return ForkTaken::Unknown;
        }
        if !proof.verify() {
            return ForkTaken::Invalid;
        }
        if c.proof.is_some_and(|held| held.place() <= proof.place()) {
            return ForkTaken::Held;
        }
        c.proof = Some(*proof);
        self.freeze(chain, proof.place());
        ForkTaken::Lowered
    }

    fn events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    fn walk(&self, chain: ChainId) -> Option<Walk> {
        self.walks.get(&chain).map(|(lowest, next, _)| Walk {
            lowest: *lowest,
            next: *next,
        })
    }

    fn walk_extend(
        &mut self,
        chain: ChainId,
        lowest: u64,
        next: ChangeHash,
        hashes: &[ChangeHash],
    ) -> bool {
        let held: usize = self.walks.values().map(|(_, _, hashes)| hashes.len()).sum();
        if self
            .walk_ceiling
            .is_some_and(|most| held + hashes.len() > most)
        {
            self.walks.remove(&chain);
            return false;
        }
        let walk = self
            .walks
            .entry(chain)
            .or_insert((u64::MAX, ChangeHash::ZERO, BTreeMap::new()));
        for (i, hash) in hashes.iter().enumerate() {
            walk.2.insert(lowest + i as u64, *hash);
        }
        walk.0 = lowest;
        walk.1 = next;
        true
    }

    fn walk_end(&mut self, chain: ChainId) {
        self.walks.remove(&chain);
    }
}

impl Model {
    /// The hash the walk of `chain` checked at `seq`.
    pub fn walk_hash(&self, chain: ChainId, seq: u64) -> Option<ChangeHash> {
        self.walks.get(&chain)?.2.get(&seq).copied()
    }

    /// The body `envelope` carries, if this replica can open it: the key
    /// of the epoch it names is here, it is sealed for this share, and it
    /// opens and matches its head. Otherwise the sealing is declined on
    /// its link, and nothing stops.
    fn open(&self, envelope: &Envelope<'_>, head: &Head) -> Option<ModelBody> {
        if !self.keys.contains(&envelope.epoch()) || envelope.project() != SHARE {
            return None;
        }
        open(envelope, head)
    }

    /// Judges `signed`, the start of a chain not known here: only a start
    /// makes a chain known (sync §4.3).
    fn admit_start(&mut self, signed: SignedHead, envelope: &Envelope<'_>) -> Admission {
        let head = signed.head;
        let chain = head.chain;
        let Some(origin) = head.origin else {
            return Admission::TurnedAway;
        };
        if !signed.verify(origin.author) {
            return Admission::Invalid;
        }
        // A listed start is taken only as the walk checked it.
        let listed = self.listed(chain).is_some();
        if listed && self.walk_hash(chain, 1) != Some(signed.hash()) {
            return Admission::TurnedAway;
        }
        let Some(body) = self.open(envelope, &head) else {
            return Admission::Declined;
        };
        let ModelBody::Start { share, binary, .. } = body else {
            return Admission::TurnedAway;
        };
        if binary != self.binary {
            return Admission::TurnedAway;
        }
        let members = self.members();
        let (grant, never) = match share {
            // The journal knows only the pin: a prefix's start is of the
            // share if the first record lists its chain, and is taken on
            // the record alone.
            None if listed => (None, None),
            None => return Admission::TurnedAway,
            Some(under) if under.genesis != self.share() => return Admission::TurnedAway,
            Some(under) => {
                // Its grant's record is not here yet: asked for again
                // when records arrive.
                if under.grant > self.records.len() as u64 {
                    return Admission::Declined;
                }
                if !members.ever.contains(&origin.author) {
                    return Admission::TurnedAway;
                }
                let never = if members.grant(under.grant, origin.author).is_none() {
                    Some("a start whose grant does not set its author's entry")
                } else if members
                    .closed(chain, under.grant, origin.author)
                    .is_some_and(|(_, named)| !named)
                {
                    Some("a start of a chain closed at its start")
                } else {
                    None
                };
                (Some(under.grant), never)
            }
        };
        self.chains.insert(
            chain,
            Chain {
                origin,
                grant,
                changes: Vec::new(),
                frozen: None,
                proof: None,
                refused: None,
            },
        );
        self.events.push(Event::Known(chain));
        self.apply(chain, signed, envelope.bytes().to_vec());
        if let Some(why) = never {
            // Kept as the witness of whose and what the chain is; nothing
            // of it is taken past it.
            self.refuse(chain, 1, signed);
            return Admission::Never { why: Why::new(why) };
        }
        Admission::Applied
    }

    fn refuse(&mut self, chain: ChainId, seq: u64, head: SignedHead) {
        if let Some(c) = self.chains.get_mut(&chain) {
            c.refused = Some(head);
        }
        self.freeze(chain, seq);
    }
}

/// One peer: its identity, storage, machine and budget.
#[derive(Debug)]
pub struct Peer {
    /// Its signer.
    pub signer: Signer,
    /// Its storage.
    pub model: Model,
    /// Its machine.
    pub machine: Machine,
    /// Its budget.
    pub budget: Counting,
    /// The record that last set its entry, as its own records say.
    pub grant: Option<u64>,
    /// Its own chain's origin: of a chain begun under `grant`.
    pub origin: ChainOrigin,
    /// Pages to build.
    pub jobs: VecDeque<Job>,
}

impl Peer {
    /// Its key.
    pub fn key(&self) -> PublicKey {
        self.signer.public()
    }

    /// Its own chain.
    pub fn chain(&self) -> ChainId {
        self.origin.chain()
    }

    /// Begins a new chain whenever its records set its own entry again
    /// (sync §4.3): its chains of earlier grants stay as they are.
    pub fn regrant(&mut self) {
        let grant = self.model.members().grant_of(self.key());
        if grant != self.grant {
            self.grant = grant;
            self.origin.salt = salt(grant);
        }
    }
}

/// The salt of a peer's chain begun under `grant`.
fn salt(grant: Option<u64>) -> [u8; 16] {
    let mut salt = [7; 16];
    salt[..8].copy_from_slice(&grant.unwrap_or(0).to_be_bytes());
    salt
}

/// A link between two peers, each side's id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wire {
    /// The peers.
    pub ends: (usize, usize),
    /// Each end's id for it.
    pub ids: (LinkId, LinkId),
}

/// Peers and the links between them.
#[derive(Debug)]
pub struct Net {
    /// The peers.
    pub peers: Vec<Peer>,
    /// Links up, by the pair of peers (lower first).
    pub wires: BTreeMap<(usize, usize), Wire>,
    /// Messages in flight, per direction (from, to), in order.
    pub flight: BTreeMap<(usize, usize), VecDeque<Send>>,
    /// The time.
    pub now: Duration,
    /// Link ids handed out.
    next_link: u64,
    /// Effects seen, per peer.
    pub effects: Vec<Vec<Effect>>,
    /// Messages each peer's machine took, by name, for whitelists.
    pub delivered: Vec<(usize, usize, Sync)>,
    /// Every tip each peer has held, after each of its machine's calls.
    pub history: Vec<BTreeSet<(ChainId, u64, ChangeHash, u64)>>,
    /// Messages a link sent while it was not Reader that Bootstrap does
    /// not allow: each a fault of the machine.
    pub early: Vec<(usize, &'static str)>,
    /// Links each peer closed, and why.
    pub closes: Vec<(usize, Closed)>,
    /// Whether to keep every delivered message (scenarios) or not.
    pub keep: bool,
}

/// A seed for peer `i`.
pub fn seed(i: usize) -> [u8; 32] {
    let mut seed = [0; 32];
    seed[0] = u8::try_from(i).unwrap() + 1;
    seed
}

impl Net {
    /// `n` peers; peer 0 is the owner, and every other is added as an
    /// editor, each record taken by every peer.
    pub fn new(n: usize) -> Self {
        Self::with(n, n, Vec::new())
    }

    /// `n` peers of which the first `members` are members (all editors),
    /// with `before` listed in the first record.
    pub fn with(n: usize, members: usize, before: Vec<([u8; 16], u64, [u8; 32])>) -> Self {
        let signers: Vec<Signer> = (0..n).map(|i| Signer::from_seed(&seed(i))).collect();
        let mut records = Vec::new();
        let create = Record {
            seq: 1,
            prev: [0; 32],
            op: Op::Create {
                owner: signers[0].public().0,
                before,
            },
        };
        records.push(create.bytes());
        for signer in signers.iter().take(members).skip(1) {
            let prev = record_hash(records.last().unwrap());
            let record = Record {
                seq: records.len() as u64 + 1,
                prev,
                op: Op::Add {
                    key: signer.public().0,
                    editor: true,
                },
            };
            records.push(record.bytes());
        }
        let peers = signers
            .into_iter()
            .enumerate()
            .map(|(i, signer)| {
                let key = signer.public();
                let origin = ChainOrigin {
                    author: key,
                    project: ProjectId([u8::try_from(i).unwrap(); 16]),
                    salt: salt(None),
                };
                let mut peer = Peer {
                    model: Model::new(key, records.clone()),
                    machine: Machine::new(),
                    budget: Counting::default(),
                    grant: None,
                    origin,
                    jobs: VecDeque::new(),
                    signer,
                };
                peer.regrant();
                peer
            })
            .collect();
        Self {
            peers,
            wires: BTreeMap::new(),
            flight: BTreeMap::new(),
            now: Duration::from_secs(1),
            next_link: 0,
            effects: vec![Vec::new(); n],
            delivered: Vec::new(),
            history: vec![BTreeSet::new(); n],
            early: Vec::new(),
            closes: Vec::new(),
            keep: true,
        }
    }

    fn take_output(&mut self, peer: usize, output: Output) {
        self.peers[peer].regrant();
        let tips = self.peers[peer].model.tips_after(None, None, usize::MAX).0;
        self.history[peer].extend(tips.iter().map(|t| (t.chain, t.seq, t.hash, t.fork)));
        for send in output.sends {
            if !send.message.in_bootstrap()
                && self.peers[peer].machine.phase(send.link) == Some(Phase::Bootstrap)
            {
                self.early.push((peer, send.message.name()));
            }
            let Some(to) = self.peer_of(peer, send.link) else {
                continue;
            };
            self.flight.entry((peer, to)).or_default().push_back(send);
        }
        for effect in output.effects {
            match &effect {
                Effect::Serve(job) => self.peers[peer].jobs.push_back(*job),
                Effect::Close { link, why } => {
                    self.closes.push((peer, *why));
                    self.unlink_id(peer, *link);
                }
                Effect::Reader(_)
                | Effect::Refused { .. }
                | Effect::Diverged { .. }
                | Effect::Unlinked { .. } => {}
            }
            self.effects[peer].push(effect);
        }
    }

    /// The peer at the other end of `peer`'s `link`.
    fn peer_of(&self, peer: usize, link: LinkId) -> Option<usize> {
        self.wires.values().find_map(|wire| {
            if wire.ends.0 == peer && wire.ids.0 == link {
                Some(wire.ends.1)
            } else if wire.ends.1 == peer && wire.ids.1 == link {
                Some(wire.ends.0)
            } else {
                None
            }
        })
    }

    /// `peer`'s link id to `other`.
    pub fn link_id(&self, peer: usize, other: usize) -> Option<LinkId> {
        let key = (peer.min(other), peer.max(other));
        let wire = self.wires.get(&key)?;
        Some(if wire.ends.0 == peer {
            wire.ids.0
        } else {
            wire.ids.1
        })
    }

    /// Links `a` and `b`, if both are members of each other's chain (as
    /// the transport's verdict would), and not linked.
    pub fn link(&mut self, a: usize, b: usize) {
        if a == b {
            return;
        }
        let key = (a.min(b), a.max(b));
        if self.wires.contains_key(&key) {
            return;
        }
        let (ka, kb) = (self.peers[a].key(), self.peers[b].key());
        if !self.peers[a].model.is_member(kb) && !self.peers[b].model.is_member(ka) {
            return;
        }
        let ids = (LinkId(self.next_link), LinkId(self.next_link + 1));
        self.next_link += 2;
        let (lo, hi) = key;
        self.wires.insert(key, Wire { ends: key, ids });
        for (me, id, them) in [(lo, ids.0, hi), (hi, ids.1, lo)] {
            let remote = self.peers[them].key();
            let peer = &mut self.peers[me];
            let output = peer.machine.on_local(
                &mut peer.model,
                &mut peer.budget,
                self.now,
                Local::Linked { link: id, remote },
            );
            self.take_output(me, output);
        }
    }

    /// Drops the link between `a` and `b`.
    pub fn unlink(&mut self, a: usize, b: usize) {
        let key = (a.min(b), a.max(b));
        let Some(wire) = self.wires.remove(&key) else {
            return;
        };
        self.flight.remove(&(a, b));
        self.flight.remove(&(b, a));
        for (me, id) in [(wire.ends.0, wire.ids.0), (wire.ends.1, wire.ids.1)] {
            let peer = &mut self.peers[me];
            let output = peer.machine.on_local(
                &mut peer.model,
                &mut peer.budget,
                self.now,
                Local::Unlinked(id),
            );
            peer.jobs.retain(|job| job.link != id);
            self.take_output(me, output);
        }
    }

    fn unlink_id(&mut self, peer: usize, link: LinkId) {
        if let Some(other) = self.peer_of(peer, link) {
            self.unlink(peer, other);
        }
    }

    /// Delivers the next message from `from` to `to`, if any; true if one
    /// was.
    pub fn deliver(&mut self, from: usize, to: usize) -> bool {
        let Some(send) = self
            .flight
            .get_mut(&(from, to))
            .and_then(VecDeque::pop_front)
        else {
            return false;
        };
        let sender = &self.peers[from];
        if !sender.machine.is_current(send.link, send.generation) {
            return true;
        }
        self.deliver_message(from, to, &send.message);
        true
    }

    /// Delivers `message` as if `from` sent it to `to` now.
    pub fn deliver_message(&mut self, from: usize, to: usize, message: &Sync) {
        let Some(link) = self.link_id(to, from) else {
            return;
        };
        if self.keep {
            self.delivered.push((from, to, message.clone()));
        }
        let bytes = message.encode().unwrap();
        let peer = &mut self.peers[to];
        let output =
            peer.machine
                .on_message(&mut peer.model, &mut peer.budget, self.now, link, &bytes);
        self.take_output(to, output);
    }

    /// Builds `peer`'s next page, as a writer holding a permit would.
    pub fn serve(&mut self, peer: usize) -> bool {
        let Some(job) = self.peers[peer].jobs.pop_front() else {
            return false;
        };
        let p = &mut self.peers[peer];
        if let Some(send) = p.machine.serve(&mut p.model, &mut p.budget, &job)
            && let Some(to) = self.peer_of(peer, send.link)
        {
            self.flight.entry((peer, to)).or_default().push_back(send);
        }
        true
    }

    /// Lets `by` pass on every peer.
    pub fn tick(&mut self, by: Duration) {
        self.now += by;
        for i in 0..self.peers.len() {
            let peer = &mut self.peers[i];
            let output = peer
                .machine
                .on_timer(&mut peer.model, &mut peer.budget, self.now);
            self.take_output(i, output);
        }
    }

    /// Tells `peer`'s machine its journal changed.
    pub fn journal(&mut self, peer: usize) {
        let p = &mut self.peers[peer];
        let output = p
            .machine
            .on_local(&mut p.model, &mut p.budget, self.now, Local::Journal);
        self.take_output(peer, output);
    }

    /// Tells `peer`'s machine of `local`.
    pub fn local(&mut self, peer: usize, local: Local) {
        let p = &mut self.peers[peer];
        let output = p
            .machine
            .on_local(&mut p.model, &mut p.budget, self.now, local);
        self.take_output(peer, output);
    }

    /// Delivers everything in flight and builds every page, until none
    /// is left (at most `rounds` passes).
    pub fn drain(&mut self, rounds: usize) {
        for _ in 0..rounds {
            let mut any = false;
            for i in 0..self.peers.len() {
                while self.serve(i) {
                    any = true;
                }
            }
            let pairs: Vec<(usize, usize)> = self.flight.keys().copied().collect();
            for (from, to) in pairs {
                while self.deliver(from, to) {
                    any = true;
                }
            }
            if !any {
                return;
            }
        }
    }

    /// Delivers, ticks and delivers again until `seconds` have passed.
    pub fn settle(&mut self, seconds: u64) {
        for _ in 0..seconds {
            self.drain(64);
            self.tick(Duration::from_secs(1));
        }
        self.drain(64);
    }

    /// Links every pair of peers.
    pub fn link_all(&mut self) {
        for a in 0..self.peers.len() {
            for b in a + 1..self.peers.len() {
                self.link(a, b);
            }
        }
    }

    /// `peer` makes a change on its own chain naming `deps` (its start
    /// first, if its chain has none).
    pub fn change(&mut self, peer: usize, deps: Vec<ChangeId>) -> Option<ChangeId> {
        self.change_in(peer, deps, 0)
    }

    /// As [`Self::change`], sealed in `epoch`.
    pub fn change_in(&mut self, peer: usize, deps: Vec<ChangeId>, epoch: u32) -> Option<ChangeId> {
        self.start(peer);
        let p = &mut self.peers[peer];
        let chain = p.chain();
        let tip = p.model.tip(chain)?;
        if tip.fork != 0 || p.model.frozen(chain).is_some() {
            return None;
        }
        let body = ModelBody::Edit {
            deps: deps.iter().map(|d| (d.chain.0, d.seq)).collect(),
            never: false,
            blind: 0,
        };
        let head = sign(&p.signer, p.origin, tip.seq + 1, tip.hash, &body);
        let envelope = seal_in(head, &body, epoch);
        p.model.commit(envelope);
        let id = head.id();
        self.journal(peer);
        Some(id)
    }

    /// `peer` makes its chain's start if it has none, under its grant.
    pub fn start(&mut self, peer: usize) {
        let p = &mut self.peers[peer];
        if p.model.chains.contains_key(&p.chain()) {
            return;
        }
        let body = ModelBody::Start {
            share: Some(Under {
                genesis: p.model.share(),
                grant: p.grant.unwrap_or(0),
            }),
            binary: BINARY,
            blind: 0,
        };
        let head = sign(&p.signer, p.origin, 1, ChangeHash::ZERO, &body);
        p.model.commit(seal(head, &body));
        self.journal(peer);
    }

    /// The owner (peer 0) appends `op` and takes it.
    pub fn record(&mut self, op: Op) {
        let owner = &mut self.peers[0];
        let records = &owner.model.records;
        let record = Record {
            seq: records.len() as u64 + 1,
            prev: record_hash(records.last().unwrap()),
            op,
        };
        let taken = owner.model.take_own(&record.bytes());
        self.local(0, Local::Membership(taken));
    }

    /// The cut a record lowering `key` carries: each chain of theirs the
    /// owner holds, and the last change it has of it. A chain the owner
    /// never saw is not named, and so is closed at its start.
    pub fn cuts(&self, key: PublicKey) -> Vec<([u8; 16], u64)> {
        let owner = &self.peers[0].model;
        owner
            .chains
            .iter()
            .filter(|(_, c)| c.origin.author == key)
            .filter_map(|(chain, _)| Some((chain.0, owner.tip(*chain)?.seq.max(1))))
            .collect()
    }

    /// Restarts `peer`: its links drop, its machine is new, its held
    /// cache and unread events are lost; its durable state stays.
    pub fn restart(&mut self, peer: usize) {
        let others: Vec<usize> = (0..self.peers.len()).filter(|o| *o != peer).collect();
        for other in others {
            self.unlink(peer, other);
        }
        let p = &mut self.peers[peer];
        p.machine = Machine::new();
        p.jobs.clear();
        p.model.restart();
    }

    /// Whether `peer`'s link to `other` is Reader.
    pub fn reader(&self, peer: usize, other: usize) -> bool {
        self.link_id(peer, other)
            .and_then(|link| self.peers[peer].machine.phase(link))
            == Some(Phase::Reader)
    }

    /// What `peer`'s link to `other` was told of `chain`.
    pub fn told(&self, peer: usize, other: usize, chain: ChainId) -> Option<Told> {
        let link = self.link_id(peer, other)?;
        self.peers[peer].machine.told(link, chain)
    }

    /// `author` signs another change at the number after its tip, which
    /// reaches only `target` (as from a second install of the author):
    /// the author's own next change is then a fork of it.
    pub fn fork_into(&mut self, author: usize, target: usize) -> Option<ChangeId> {
        self.start(author);
        let a = &self.peers[author];
        let tip = a.model.tip(a.chain())?;
        let body = ModelBody::Edit {
            deps: Vec::new(),
            never: false,
            blind: 1,
        };
        let head = sign(&a.signer, a.origin, tip.seq + 1, tip.hash, &body);
        let envelope = seal(head, &body);
        let key = a.key();
        let t = &mut self.peers[target].model;
        let parsed = Envelope::parse(&envelope).unwrap();
        t.admit(key, &parsed);
        self.journal(target);
        Some(head.id())
    }

    /// `author`'s change of `body` at the number after its tip, admitted
    /// by `target` alone.
    pub fn give(&mut self, author: usize, target: usize, body: &ModelBody) -> Admission {
        let a = &self.peers[author];
        let tip = a.model.tip(a.chain()).unwrap();
        let head = sign(&a.signer, a.origin, tip.seq + 1, tip.hash, body);
        let envelope = seal(head, body);
        let key = a.key();
        let parsed = Envelope::parse(&envelope).unwrap();
        let admission = self.peers[target].model.admit(key, &parsed);
        self.journal(target);
        admission
    }

    /// A chain of `peer`'s from before the share, of `n` changes (start
    /// included), salted with `salt`, held by `holders` (as if each had
    /// it before the share): its id, and each change's head and envelope.
    pub fn prior_chain(
        &mut self,
        peer: usize,
        n: u64,
        salt: u8,
        holders: &[usize],
    ) -> (ChainOrigin, Vec<(SignedHead, Vec<u8>)>) {
        let p = &self.peers[peer];
        let origin = ChainOrigin {
            author: p.key(),
            project: ProjectId([0xee; 16]),
            salt: [salt; 16],
        };
        let changes = prior(&p.signer, origin, n, 0);
        for holder in holders {
            self.peers[*holder]
                .model
                .chains
                .insert(origin.chain(), Chain::prior(origin, changes.clone()));
        }
        (origin, changes)
    }
}

/// `n` changes of `origin`'s chain from its start (bound to no share),
/// their bodies differing by `blind`.
pub fn prior(
    signer: &Signer,
    origin: ChainOrigin,
    n: u64,
    blind: u8,
) -> Vec<(SignedHead, Vec<u8>)> {
    branch(signer, origin, &[], n, blind)
}

/// `base` continued to `n` changes of `origin`'s chain (from a start bound
/// to no share if `base` is empty), the new bodies differing by `blind`.
pub fn branch(
    signer: &Signer,
    origin: ChainOrigin,
    base: &[(SignedHead, Vec<u8>)],
    n: u64,
    blind: u8,
) -> Vec<(SignedHead, Vec<u8>)> {
    let mut changes = base.to_vec();
    let mut prev = base.last().map_or(ChangeHash::ZERO, |(h, _)| h.hash());
    for seq in base.len() as u64 + 1..=n {
        let body = if seq == 1 {
            ModelBody::Start {
                share: None,
                binary: BINARY,
                blind,
            }
        } else {
            ModelBody::Edit {
                deps: Vec::new(),
                never: false,
                blind,
            }
        };
        let head = sign(signer, origin, seq, prev, &body);
        prev = head.hash();
        changes.push((head, seal(head, &body)));
    }
    changes
}
