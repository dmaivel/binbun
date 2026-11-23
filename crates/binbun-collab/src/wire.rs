//! The messages peers send on each lane, postcard in frames
//! ([`crate::transport::write_frame`]). The
//! numbers in [`Control::Hello`] say which messages a peer speaks: a
//! different protocol or log major cannot join.
//!
//! Each kind of message has its frame limit ([`Frame::LIMIT`]), checked
//! before a frame's body is read; [`encode`] is the one encoder of them
//! and fails before its buffer passes the limit, [`decode`] the one
//! decoder, through [`bounded::decode`]: every list and string in a
//! message is a bounded type, so decoding allocates no more than the
//! message's kind declares. The sync lane carries [`binbun_sync::Sync`],
//! whose frames are checked against [`binbun_sync::wire::FRAME`] (in
//! Bootstrap [`binbun_sync::wire::BOOTSTRAP_FRAME`]) and decoded by the
//! sync machine.

use std::fmt;

use binbun_bounded::{self as bounded, Bounds, Bytes, Page, Text};
use binbun_session::journal::{BlobId, EngineVersion, ProjectId};
use binbun_sync::wire::RECORDS_BYTES;
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::membership::{MAX_RECORD, Role, SignedRecord};
use crate::ticket::Card;

/// The ALPN of binbun's peer protocol.
pub const ALPN: &[u8] = b"binbun/collab/1";

/// The messages' version.
pub const PROTOCOL: u32 = 1;

/// The change log's major version.
pub const LOG: u32 = 1;

/// The features this build has, told in a hello and a welcome: none in
/// 0.1 (bit 0 will say sets, bit 1 stores).
pub const FEATURES: u32 = 0;

/// The most bytes of a control frame ([`Control`]): a host reads one
/// from anyone who dials, before it knows whether they are a member or
/// invited.
pub const CONTROL_FRAME: usize = 16 << 10;

/// The most bytes of a host's answer as its dialler reads it
/// ([`Answer`]): a kick's page of records filled to [`KICK_BYTES`], one
/// record past it, and the rest of the frame.
pub const ANSWER_FRAME: usize = KICK_BYTES + MAX_RECORD + CONTROL_FRAME;

/// The bytes of records a kick's page is filled to: one record more is
/// taken past them, so a record of [`MAX_RECORD`] bytes always fits.
pub const KICK_BYTES: usize = RECORDS_BYTES;

/// The most bytes of a blob stream's ask ([`BlobAsk`]).
pub const BLOB_ASK_FRAME: usize = 1 << 10;

/// The most bytes of a blob stream's answer ([`BlobAnswer`]).
pub const BLOB_ANSWER_FRAME: usize = 16 << 10;

/// The most bytes of a live lane's frame ([`LiveFrame`]).
pub const LIVE_FRAME: usize = 16 << 10;

/// The most bytes of the sealed offers in a [`BlobAnswer`].
pub const MAX_SEALED_OFFERS: usize = BLOB_ANSWER_FRAME - 32;

/// The most bytes of a live frame's sealed [`crate::live::Said`].
pub const MAX_LIVE_SEALED: usize = LIVE_FRAME - 4;

/// The most bytes of why something was refused or done, as a message
/// tells it.
pub const MAX_REASON: usize = 1024;

/// The most bytes of a binbun's release or build as a peer tells them:
/// 128 characters ([`crate::live`]).
pub const MAX_LABEL: usize = 512;

/// The most membership records a [`Control::Kick`] carries; fewer past
/// [`KICK_BYTES`].
pub const MAX_KICK_RECORDS: usize = 64;

/// A kind of message: its frame limit.
pub trait Frame: Serialize {
    /// The most bytes of its frame's body.
    const LIMIT: usize;
}

/// `message`'s postcard, within its kind's frame limit: its buffer never
/// grows past it.
///
/// # Errors
///
/// It does not fit its frame, or does not encode.
pub fn encode<T: Frame>(message: &T) -> Result<Vec<u8>, Error> {
    bounded::encode(message, T::LIMIT)
        .map_err(|error| Error::new(format!("a message that cannot be sent: {error}")))
}

/// The message `bytes` hold, all of them, within its kind's frame limit
/// and bounds.
///
/// # Errors
///
/// They pass the limit, do not read within the message's bounds, or
/// bytes are left over.
pub fn decode<T: Frame + Bounds>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > T::LIMIT {
        return Err(Error::new("a message larger than its frame"));
    }
    bounded::decode(bytes)
        .map_err(|error| Error::new(format!("a message that does not read: {error}")))
}

/// The binbun a peer runs, as a hello or an introduction tells it: its
/// release and build ([`EngineVersion`]), each of [`MAX_LABEL`] bytes at
/// most. Encoded as the [`EngineVersion`] is.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Engine {
    /// The release.
    pub release: Text<MAX_LABEL>,
    /// The build.
    pub build: Text<MAX_LABEL>,
}

impl Engine {
    /// `engine`, each label cut to [`MAX_LABEL`] bytes.
    pub fn of(engine: &EngineVersion) -> Self {
        Self {
            release: Text::truncated(&engine.release),
            build: Text::truncated(&engine.build),
        }
    }

    /// As the session names it.
    pub fn version(&self) -> EngineVersion {
        EngineVersion {
            release: self.release.to_string(),
            build: self.build.to_string(),
        }
    }
}

impl Bounds for Engine {}

/// A dialler's first words: to join, or to sync as a member.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// [`PROTOCOL`].
    pub protocol: u32,
    /// [`LOG`].
    pub log: u32,
    /// The binbun asking.
    pub engine: Engine,
    /// The shared project.
    pub project: ProjectId,
    /// The ticket's invite, if joining by one.
    pub invite: Option<[u8; 16]>,
    /// Who asks: their identity card.
    pub card: Card,
    /// The membership chain's head the dialler holds, number and hash
    /// (zeros before the first record): where a kick's records begin.
    pub membership: (u64, [u8; 32]),
    /// The features its build has ([`FEATURES`]).
    pub features: u32,
}

/// Without the invite: whoever reads debug output must not join by it.
impl fmt::Debug for Hello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hello")
            .field("protocol", &self.protocol)
            .field("log", &self.log)
            .field("engine", &self.engine)
            .field("project", &self.project)
            .field("invite", &self.invite.map(|_| "…"))
            .field("card", &self.card)
            .field("membership", &self.membership.0)
            .field("features", &self.features)
            .finish()
    }
}

/// Joining and leaving (the [`crate::transport::Lane::Control`] lane):
/// the dialler says hello, the host answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Control {
    /// Asks to join, or to sync as a member.
    Hello(Box<Hello>),
    /// The host is asking whoever approves.
    Pending,
    /// In, with this role.
    Welcome {
        /// The role.
        role: Role,
        /// Why the dialler is view-only in this session (it runs another
        /// build than the host), if it is.
        view_only: Option<Text<MAX_REASON>>,
        /// The features the host's build has ([`FEATURES`]).
        features: u32,
    },
    /// Not in, and why.
    Denied {
        /// Why.
        reason: Text<MAX_REASON>,
    },
    /// Put out (removed), and why, with the membership records saying so:
    /// a page of those after the head the member holds, in order, through
    /// its removal and none after it; `more` if the page stops short of
    /// the removal, which a dial again from the new head goes on with.
    Kick {
        /// Why.
        reason: Text<MAX_REASON>,
        /// The records.
        records: Page<SignedRecord, MAX_KICK_RECORDS>,
    },
}

impl Frame for Control {
    const LIMIT: usize = CONTROL_FRAME;
}

impl Bounds for Control {}

/// A host's answer as its dialler reads it: a [`Control`] within
/// [`ANSWER_FRAME`] bytes, as a kick holding a record of [`MAX_RECORD`]
/// bytes needs. What a host reads from whoever dials stays within
/// [`CONTROL_FRAME`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Answer(pub Control);

impl Frame for Answer {
    const LIMIT: usize = ANSWER_FRAME;
}

impl Bounds for Answer {}

impl Control {
    /// A kick saying `reason`, with a page of `records` (those after the
    /// head the member holds through its removal, in order): filled to
    /// [`KICK_BYTES`] and one record past them, [`MAX_KICK_RECORDS`] at
    /// most, so the first always goes; `more` only with a record and if
    /// one is left out.
    pub fn kick(reason: &str, records: &[SignedRecord]) -> Self {
        let reason = Text::truncated(reason);
        let empty = Self::Kick {
            reason: reason.clone(),
            records: Page::default(),
        };
        // The page's room: the frame's, less the kick around an empty
        // page (whose own 2 bytes the builder counts).
        let around = bounded::size(&empty, ANSWER_FRAME).map_or(ANSWER_FRAME, |size| size - 2);
        let mut page = bounded::PageBuilder::new(ANSWER_FRAME.saturating_sub(around));
        let mut left = false;
        for record in records {
            if page.used() >= KICK_BYTES {
                left = true;
                break;
            }
            if page.push(record.clone()).is_err() {
                break;
            }
        }
        let mut records = page.finish();
        records.more = (records.more || left) && !records.items.is_empty();
        Self::Kick { reason, records }
    }
}

/// What a stream of the [`crate::transport::Lane::Blob`] lane asks first
/// ([`crate::blobs`]). Before a link is a reader's only [`Self::Home`]
/// and a [`Self::Get`] of what it offered are answered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobAsk {
    /// The blobs the peer offers.
    Offers,
    /// This blob: once [`BlobAnswer::Serving`], the rest of the stream is
    /// iroh-blobs' get protocol (its request, then the blob's verified
    /// ranges the asker lacks).
    Get(BlobId),
    /// The offer of the binary the membership chain names, if the peer
    /// offers that file: what a joiner without it may ask before its link
    /// is a reader's (sync §3.6). Answered as [`Self::Offers`], with that
    /// offer alone.
    Home,
}

impl Frame for BlobAsk {
    const LIMIT: usize = BLOB_ASK_FRAME;
}

impl Bounds for BlobAsk {}

/// The answer to a [`BlobAsk`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobAnswer {
    /// The offers, `nonce:24 ‖ XChaCha20-Poly1305(postcard(Vec<Offer>))`
    /// under epoch `epoch`'s `blobkey` subkey
    /// ([`crate::blobs::decode_offers`]).
    Offers {
        /// The epoch whose key sealed them.
        epoch: u32,
        /// The sealed offers.
        sealed: Bytes<MAX_SEALED_OFFERS>,
    },
    /// The blob asked for follows.
    Serving,
    /// Not served, and why.
    Refused(Text<MAX_REASON>),
}

impl Frame for BlobAnswer {
    const LIMIT: usize = BLOB_ANSWER_FRAME;
}

impl Bounds for BlobAnswer {}

/// A frame of the [`crate::transport::Lane::Live`] lane:
/// `nonce:24 ‖ XChaCha20-Poly1305(postcard(Said))` ([`crate::live`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveFrame(pub Bytes<MAX_LIVE_SEALED>);

impl Frame for LiveFrame {
    const LIMIT: usize = LIVE_FRAME;
}

impl Bounds for LiveFrame {}

/// A signature as messages carry it, read as exactly 64 bytes
/// ([`binbun_bounded::Exact`]), for `#[serde(with = "crate::wire::signature")]`:
/// the encoding of ed25519's own, whose decoder [`bounded::walk`] cannot
/// tell from an unbounded one.
pub(crate) mod signature {
    use binbun_bounded::Exact;
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Writes `sig`.
    pub(crate) fn serialize<S: Serializer>(
        sig: &Signature,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Exact::from(sig.to_bytes()).serialize(serializer)
    }

    /// Reads a signature.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Signature, D::Error> {
        Exact::<64>::deserialize(deserializer).map(|bytes| Signature::from_bytes(bytes.as_array()))
    }
}

#[cfg(test)]
mod tests {
    use binbun_bounded::{Bounds, Bytes, walk};
    use ed25519_dalek::Signature;

    use super::{
        ANSWER_FRAME, Answer, BlobAnswer, BlobAsk, Control, Engine, LiveFrame, decode, encode,
    };
    use crate::blobs::Offer;
    use crate::live::{Presence, Said};
    use crate::membership::{Binary, MAX_RECORD, Record, SignedRecord};
    use crate::ticket::{Card, JoinTicket, PeerAddr};

    /// Whether `T`, marked bounded, is: every list and string in it, in
    /// every variant.
    fn bounded<T: Bounds>() {
        if let Err(error) = walk::<T>() {
            panic!("{}: {error}", std::any::type_name::<T>());
        }
    }

    #[test]
    fn every_type_read_from_another_party_has_bounds() {
        // The messages of each lane, and what is read after opening or
        // from a text another party wrote.
        bounded::<Control>();
        bounded::<BlobAsk>();
        bounded::<BlobAnswer>();
        bounded::<LiveFrame>();
        bounded::<Said>();
        bounded::<Presence>();
        bounded::<Engine>();
        bounded::<Offer>();
        bounded::<SignedRecord>();
        bounded::<Record>();
        bounded::<Binary>();
        bounded::<Card>();
        bounded::<PeerAddr>();
        bounded::<JoinTicket>();
        bounded::<binbun_sync::Sync>();
    }

    #[test]
    fn a_signature_is_written_as_ed25519_writes_it() {
        let record = SignedRecord {
            bytes: Bytes::try_from(vec![1, 2]).unwrap(),
            sig: Signature::from_bytes(&[9; 64]),
        };
        let ours = postcard::to_allocvec(&record).unwrap();
        let theirs = postcard::to_allocvec(&(vec![1u8, 2], record.sig)).unwrap();
        assert_eq!(ours, theirs);
        assert_eq!(
            binbun_bounded::decode::<SignedRecord>(&ours).unwrap(),
            record
        );
    }

    #[test]
    fn a_kick_pages_its_records_in_order_and_always_holds_the_first() {
        let record = |n: u8, size: usize| SignedRecord {
            bytes: Bytes::try_from(vec![n; size]).unwrap(),
            sig: Signature::from_bytes(&[n; 64]),
        };
        // What a kick says as its dialler reads it.
        let page = |records: &[SignedRecord]| {
            let kick = Answer(Control::kick(&"why ".repeat(300), records));
            let bytes = encode(&kick).unwrap();
            assert!(bytes.len() <= ANSWER_FRAME);
            let Ok(Answer(Control::Kick { records: page, .. })) = decode::<Answer>(&bytes) else {
                panic!("not a kick");
            };
            page
        };
        // Filled to its size and one record past it; the rest follow.
        let records: Vec<SignedRecord> = (1..=14).map(|n| record(n, 100 << 10)).collect();
        let first = page(&records);
        assert_eq!(*first.items, records[..11]);
        assert!(first.more);
        // A record of the most bytes a record has goes alone, all of it.
        let big = record(0, MAX_RECORD);
        let alone = page(std::slice::from_ref(&big));
        assert_eq!(*alone.items, [big]);
        assert!(!alone.more);
        // Nothing to say: an empty page, with nothing said to follow.
        let none = page(&[]);
        assert!(none.items.is_empty() && !none.more);
    }
}
