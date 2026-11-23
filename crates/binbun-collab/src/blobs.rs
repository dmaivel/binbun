//! Files by hash between peers: the binary, for a joiner who does not have it, and
//! the debug file a peer's analysis read, for one whose analysis lacks
//! it. Only what the sharer chose to send is offered ([`Peer::offer`]):
//! nothing by default.
//!
//! - **Sealed once, kept.** An offered file is sealed as a blob
//!   ([`crate::blob`]) under a key of its own and kept, ciphertext only,
//!   in an iroh-blobs store beside the project
//!   (`collab/<project id>/blobs/`); its id is the BLAKE3 of the
//!   ciphertext, iroh-blobs' hash. What the peer offers, with each
//!   blob's key, is kept there too (`offers.bin`), sealed under a subkey
//!   of its identity's secret. Offering the same file again offers the
//!   same blob: a fetch cut short goes on where it stopped, across
//!   restarts of either side.
//! - **Offers are sealed.** A member asks a peer what it offers on a
//!   [`Lane::Blob`] stream ([`BlobAsk::Offers`]); the answer is sealed
//!   under the epoch's `blobkey` subkey ([`BlobAnswer::Offers`]): the
//!   file's name, SHA-256, length and the blob's key cross no wire in
//!   plaintext above TLS. The share's genesis and the epoch are its
//!   associated data, so a list sealed in another share of the same
//!   routing id, under the same key, does not open.
//! - **Fetched by iroh-blobs, over binbun's link.** A member asks for one
//!   blob offered ([`BlobAsk::Get`]); the stream then carries iroh-blobs'
//!   get protocol: the ranges the asker lacks, each verified against the
//!   blob's BLAKE3 tree as it comes (a range that does not match is
//!   refused, and nothing past it kept), into a store of its own
//!   in binbun's cache, a directory per blob ([`crate::fetches`]), its
//!   own for one fetch at a time. Only members reach the lane, and a
//!   stream serves only the blob it asked for.
//! - **No more than offered.** A fetch asks for no byte past the size
//!   of the blob the offer names ([`Offer::sealed`]) and refuses one
//!   that comes; a blob of another size, or not opening into the file
//!   offered, is dropped with all that was fetched of it. A fetch cut
//!   short keeps what it verified for the next.
//! - **Opened once whole**: chunk by chunk, each authenticated, into a
//!   file of its own beside the one asked for (a random name it creates),
//!   the file's SHA-256 checked against the offer's, then put into place
//!   and the fetched ciphertext dropped. A file already at that name is
//!   never replaced: the file fetched goes beside it under a numbered
//!   name (`name (2).ext`), unless it holds the same bytes. The name is
//!   one the user chose or binbun gave ([`crate::fetches::local_name`]),
//!   never the one offered, and never in binbun's projects folder.
//! - **A universal binary** is sent whole, its offer naming the slice
//!   shared ([`Offer::arch`]), which a joiner opens.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use binbun_bounded::{self as bounded, Bounded, Bounds, Text};
use binbun_session::identity::Identity;
use binbun_session::journal::{BlobId, ProjectId, PublicKey};
use binbun_sync::Sync as Said;
use binbun_sync::wire::BOOTSTRAP_FRAME;
use binbun_sync::{LinkId, Phase};
use bytes::Bytes;
use iroh::endpoint::VarInt;
use iroh_blobs::api::proto::BlobStatus;
use iroh_blobs::api::remote::GetProgressItem;
use iroh_blobs::get::GetError;
use iroh_blobs::get::fsm::DecodeError;
use iroh_blobs::protocol::{ChunkRanges, ChunkRangesExt as _, GetRequest};
use iroh_blobs::provider::events::{
    AbortReason, EventMask, EventSender, ObserveMode, ProviderMessage, RequestMode,
};
use iroh_blobs::store::GcConfig;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::store::fs::options::Options;
use iroh_blobs::util::{
    AsyncReadRecvStream, AsyncReadRecvStreamExtra, AsyncWriteSendStream, AsyncWriteSendStreamExtra,
};
use iroh_blobs::{Hash, HashAndFormat};
use n0_future::StreamExt as _;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::blob::{self, BlobKey, HEADER, Opener};
use crate::budgets::Stream;
use crate::crypto::{self, EpochKey};
use crate::fetches::{self, Fetches};
use crate::membership::{Binary, Membership, SignedRecord};
use crate::peer::{Config, Inner, Notice, Notifier, Peer};
use crate::ticket::{Card, JoinTicket, MAX_ARCH};
use crate::transport::{
    Link, RecvStream, SendStream, Transport, read_bytes, read_frame, read_frame_body,
    read_frame_length, write_bytes, write_frame,
};
use crate::wire::{
    self, Answer, BlobAnswer, BlobAsk, Control, Engine, FEATURES, Frame as _, Hello, LOG, PROTOCOL,
};
use crate::{Error, transport::Lane};

/// What a blob holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Kind {
    /// The binary shared.
    Binary,
    /// The debug file its analysis read.
    DebugFile,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Binary => "binary",
            Self::DebugFile => "debug file",
        })
    }
}

/// A file a peer offers, as members see it (sealed: [`BlobAnswer::Offers`]).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    /// Its blob: the BLAKE3 of the ciphertext.
    pub blob: BlobId,
    /// The blob's key.
    pub key: BlobKey,
    /// The file's bytes.
    pub length: u64,
    /// The file's SHA-256.
    pub sha256: [u8; 32],
    /// What it is.
    pub kind: Kind,
    /// Its file name.
    pub name: Text<MAX_FILE_NAME>,
    /// The binary is a universal Mach-O file: the architecture of its
    /// slice shared (`x86_64`, `arm64e`), which those who fetch it open.
    pub arch: Option<Text<MAX_ARCH>>,
}

impl fmt::Debug for Offer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Offer")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("length", &self.length)
            .field("arch", &self.arch)
            .finish_non_exhaustive()
    }
}

impl Bounds for Offer {}

/// The most bytes of an offered file's name.
pub const MAX_FILE_NAME: usize = 1024;

/// The most offers in a list.
pub const MAX_OFFERS: usize = 8;

/// The most bytes of a list of offers, so that it fits
/// [`BlobAnswer::Offers`] sealed (a nonce and a tag more).
const MAX_OFFERS_BYTES: usize = wire::MAX_SEALED_OFFERS - 40;

/// `offers` as bytes: their postcard.
///
/// # Errors
///
/// More than [`MAX_OFFERS`], or more bytes than a sealed list holds.
pub(crate) fn encode_offers(offers: &[Offer]) -> Result<Vec<u8>, Error> {
    if offers.len() > MAX_OFFERS {
        return Err(Error::new(format!("more than {MAX_OFFERS} offers")));
    }
    Ok(bounded::encode(offers, MAX_OFFERS_BYTES)?)
}

/// The offers [`encode_offers`] wrote in `bytes`, within their bounds.
///
/// # Errors
///
/// They do not read.
pub fn decode_offers(bytes: &[u8]) -> Result<Vec<Offer>, Error> {
    let offers: Bounded<Offer, MAX_OFFERS> = bounded::decode(bytes)?;
    Ok(offers.into_vec())
}

impl Offer {
    /// The blob's bytes: [`blob::sealed_len`] of the file's, a function
    /// of its Padmé length.
    pub fn sealed(&self) -> u64 {
        blob::sealed_len(self.length)
    }

    /// The blob's iroh-blobs hash.
    fn hash(&self) -> Hash {
        Hash::from_bytes(self.blob.0)
    }
}

/// What a fetch is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Fetching the blob: its bytes here (those here before included).
    Fetching,
    /// Opening it: the file's bytes written.
    Opening,
}

/// How far a fetch is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// What it does.
    pub step: Step,
    /// The bytes done.
    pub done: u64,
    /// Of these.
    pub total: u64,
}

/// Hears how far a fetch is, a few times a second.
pub type OnProgress = Arc<dyn Fn(&Progress) + Send + Sync>;

/// What a fetch came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    /// The file: where asked, or beside it under a numbered name if
    /// another file was there.
    pub path: PathBuf,
    /// Its SHA-256 (the offer's).
    pub sha256: [u8; 32],
    /// Its bytes.
    pub length: u64,
    /// The blob's bytes.
    pub sealed: u64,
    /// The blob's bytes already here when the fetch began (from a fetch
    /// cut short).
    pub had: u64,
    /// The blob's bytes this fetch received.
    pub received: u64,
    /// The time fetching took.
    pub fetching: Duration,
    /// The time opening took (reading, decrypting, writing).
    pub opening: Duration,
    /// Of that, the time the AEAD took.
    pub crypto: Duration,
}

/// How often a fetch tells how far it is.
const TELL_EVERY: Duration = Duration::from_millis(100);

/// How long opening a fetch's store waits for a fetch cut short in this
/// process (its future dropped) to let go of it.
const STORE_WAIT: Duration = Duration::from_secs(10);

/// How often a store collects what no offer keeps.
const GC_EVERY: Duration = Duration::from_secs(600);

/// How long an answer sealed in an epoch whose key is not here waits for
/// it: the membership records wrapping it to this peer come on the
/// link's sync lane, which an answer on another lane may overtake.
const KEY_WAIT: Duration = Duration::from_secs(30);

/// What the shelf's offers file is sealed for.
const OFFERS: &str = "offers";

/// A peer's blobs: what it offers, in its store, and where it fetches.
pub(crate) struct Shelf {
    /// `<project>/collab/<project id>`, if the session has a project.
    dir: Option<PathBuf>,
    /// The store of the blobs offered, once opened.
    store: tokio::sync::Mutex<Option<FsStore>>,
    /// What this peer offers now.
    offered: Mutex<Vec<Offer>>,
}

impl Shelf {
    /// The shelf of a project's collaboration directory `dir`.
    pub(crate) fn new(dir: Option<PathBuf>) -> Self {
        Self {
            dir,
            store: tokio::sync::Mutex::new(None),
            offered: Mutex::new(Vec::new()),
        }
    }

    /// The collaboration directory, or why there is none.
    fn dir(&self) -> Result<&Path, Error> {
        self.dir
            .as_deref()
            .ok_or_else(|| Error::new("the session has no project to keep blobs in"))
    }

    /// The store of the blobs offered, opened at first use.
    async fn store(&self) -> Result<FsStore, Error> {
        let mut store = self.store.lock().await;
        if let Some(store) = &*store {
            return Ok(store.clone());
        }
        let root = self.dir()?.join("blobs");
        fs::create_dir_all(&root).map_err(|error| failed(&root, &error))?;
        let options = Options {
            gc: Some(GcConfig {
                interval: GC_EVERY,
                add_protected: None,
            }),
            ..Options::new(&root)
        };
        let opened = FsStore::load_with_opts(root.join("blobs.db"), options)
            .await
            .map_err(|error| Error::new(format!("{}: {error}", root.display())))?;
        *store = Some(opened.clone());
        Ok(opened)
    }

    /// What this peer offers now.
    pub(crate) fn offered(&self) -> Vec<Offer> {
        self.offered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The offer of `blob`, if offered now.
    fn offer_of(&self, blob: BlobId) -> Option<Offer> {
        self.offered().into_iter().find(|offer| offer.blob == blob)
    }

    /// Closes the store, if open.
    pub(crate) async fn close(&self) {
        if let Some(store) = self.store.lock().await.take() {
            let _ = store.shutdown().await;
        }
    }
}

/// An error of the file at `path`.
fn failed(path: &Path, error: &io::Error) -> Error {
    Error::new(format!("{}: {error}", path.display()))
}

/// The bytes of a blob served between two checks of the requester's
/// rights (sync §3.6).
const FENCE: usize = 1 << 20;

/// A blob stream's sending half that asks `serving` before each
/// [`FENCE`] bytes whether the requester may still be served, and fails
/// once not: a member removed, or the link revoked, is sent at most
/// what was let through before.
struct Fenced {
    send: SendStream,
    serving: Box<dyn Fn() -> bool + Send>,
    /// The bytes it may write before asking again.
    left: usize,
}

impl AsyncWrite for Fenced {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.left == 0 {
            if !(this.serving)() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the requester is no longer served",
                )));
            }
            this.left = FENCE;
        }
        let most = buf.len().min(this.left);
        let written = Pin::new(&mut this.send).poll_write(cx, buf.get(..most).unwrap_or(buf));
        if let Poll::Ready(Ok(n)) = written {
            this.left = this.left.saturating_sub(n);
        }
        written
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

/// A stream's receiving half as iroh-blobs reads it (behind a mutex only
/// to be `Sync`, as iroh-blobs wants: it is only ever reached through
/// `&mut`, never locked).
pub(crate) struct Reader(pub(crate) Mutex<RecvStream>);

impl AsyncReadRecvStreamExtra for Reader {
    fn inner(&mut self) -> &mut (impl AsyncRead + Unpin + Send) {
        self.0.get_mut().unwrap_or_else(PoisonError::into_inner)
    }

    fn stop(&mut self, _code: VarInt) -> io::Result<()> {
        Ok(())
    }

    fn id(&self) -> u64 {
        0
    }
}

/// A stream's sending half as iroh-blobs writes it (as [`Reader`]).
/// Dropped, it ends the stream (QUIC's finish), which ends a request.
pub(crate) struct Writer(pub(crate) Mutex<SendStream>);

impl AsyncWriteSendStreamExtra for Writer {
    fn inner(&mut self) -> &mut (impl AsyncWrite + Unpin + Send) {
        self.0.get_mut().unwrap_or_else(PoisonError::into_inner)
    }

    fn reset(&mut self, _code: VarInt) -> io::Result<()> {
        Ok(())
    }

    async fn stopped(&mut self) -> io::Result<Option<VarInt>> {
        std::future::pending().await
    }

    fn id(&self) -> u64 {
        0
    }
}

/// What a list of offers says it is for besides its key: its label, the
/// share's genesis and the epoch (`"binbun/v1/offers" ‖ genesis ‖
/// epoch:u32`); never the routing project id, which two shares can have.
fn offers_aad(genesis: &[u8; 32], epoch: u32) -> [u8; 52] {
    let mut aad = [0; 52];
    aad[..16].copy_from_slice(b"binbun/v1/offers");
    aad[16..48].copy_from_slice(genesis);
    aad[48..].copy_from_slice(&epoch.to_be_bytes());
    aad
}

/// Seals `offers` under `key` (epoch `epoch` of `project`, the share
/// whose genesis is `genesis`).
fn seal_offers(
    key: &EpochKey,
    project: ProjectId,
    genesis: &[u8; 32],
    epoch: u32,
    offers: &[Offer],
) -> Result<(u32, bounded::Bytes<{ wire::MAX_SEALED_OFFERS }>), Error> {
    let plain = Zeroizing::new(encode_offers(offers)?);
    let sealed = crypto::seal_bound(
        &key.cipher(project, "blobkey"),
        &plain,
        &offers_aad(genesis, epoch),
    )?;
    Ok((epoch, bounded::Bytes::try_from(sealed)?))
}

/// The offers sealed in `sealed` under epoch `epoch`'s key `key`, if this
/// peer holds it, in the share whose genesis is `genesis`.
fn open_offers(
    project: ProjectId,
    genesis: &[u8; 32],
    epoch: u32,
    sealed: &[u8],
    key: Option<EpochKey>,
) -> Result<Vec<Offer>, Error> {
    let key = key.ok_or_else(|| {
        Error::new(format!(
            "the offers are sealed in epoch {epoch}, whose key is not here"
        ))
    })?;
    let plain = crypto::open_bound(
        &key.cipher(project, "blobkey"),
        sealed,
        &offers_aad(genesis, epoch),
    )
    .ok_or_else(|| Error::new("the offers do not open: of another share, or tampered with"))?;
    decode_offers(&plain).map_err(|error| Error::new(format!("offers that do not read: {error}")))
}

/// What is told of a list of offers from `from` that does not open
/// (`error`), skipped.
fn skipped(from: PublicKey, error: &Error) -> String {
    format!("a list of offers from {from} skipped: {error}")
}

/// Asks the peer at the end of `link` what it offers, sealed, with the
/// epoch it is sealed in.
async fn ask_offers(link: &Arc<dyn Link>, ask: &BlobAsk) -> Result<(u32, Vec<u8>), Error> {
    let (mut send, mut recv) = link.open(Lane::Blob).await?;
    write_frame(&mut *send, ask).await?;
    match read_frame::<BlobAnswer>(&mut *recv).await? {
        Some(BlobAnswer::Offers { epoch, sealed }) => Ok((epoch, sealed.into_vec())),
        Some(BlobAnswer::Refused(why)) => Err(Error::new(why.into_string())),
        Some(BlobAnswer::Serving) | None => Err(Error::new("no offers in the answer")),
    }
}

/// A file being opened, written beside where it goes under a random name
/// (`.binbun-<32 hex digits>.part`) it creates and no other file has, its
/// handle held until it is placed. Dropped, it removes that name and no
/// other: the file stays only where it was placed.
struct Part {
    path: PathBuf,
    file: File,
}

impl Part {
    /// A new one beside `to`.
    ///
    /// # Errors
    ///
    /// No randomness; the file cannot be created.
    fn beside(to: &Path) -> Result<Self, Error> {
        let random = crypto::random::<16>()?;
        let name = format!(".binbun-{}.part", data_encoding::HEXLOWER.encode(&random));
        let path = to.with_file_name(name);
        let file = File::create_new(&path).map_err(|error| failed(&path, &error))?;
        Ok(Self { path, file })
    }
}

impl Drop for Part {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// How a fetch failed.
enum Failed {
    /// Cut short: what it verified, no more than the offer's size, is
    /// kept for the next fetch.
    Cut(Error),
    /// Refused: the blob is not the one offered (larger, of another size,
    /// or not opening into the file offered); nothing of it is kept.
    Refused(Error),
}

/// The bytes of a BLAKE3 chunk: iroh-blobs' unit of ranges.
const BLAKE3_CHUNK: u64 = 1024;

/// How many names [`place`] tries: the one asked for, then numbered.
const PLACES: u32 = 1000;

/// `to`, or for `n` above 1 its name numbered: `name (n).ext`.
fn numbered(to: &Path, n: u32) -> PathBuf {
    if n < 2 {
        return to.to_path_buf();
    }
    let mut name = to.file_stem().unwrap_or_default().to_owned();
    name.push(format!(" ({n})"));
    if let Some(extension) = to.extension() {
        name.push(".");
        name.push(extension);
    }
    to.with_file_name(name)
}

/// Whether the file at `path` holds `offer`'s file (its length, then its
/// SHA-256).
async fn same(path: &Path, offer: &Offer) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() == offer.length)
        && digest(path.to_path_buf())
            .await
            .is_ok_and(|found| found == (offer.sha256, offer.length))
}

/// Puts the file opened at `part`, `offer`'s, at `to`, or, if another
/// file is there, beside it under a numbered name ([`numbered`]): a file
/// already there is never replaced, and one of the same bytes stays in
/// place of the new. Where it is.
///
/// # Errors
///
/// A name cannot be taken; every name tried holds another file.
async fn place(part: &Path, to: &Path, offer: &Offer) -> Result<PathBuf, Error> {
    for n in 1..=PLACES {
        let at = numbered(to, n);
        match fs::hard_link(part, &at) {
            Ok(()) => return Ok(at),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            // No hard links there (FAT, some shares): the name taken
            // first, then the file renamed onto it.
            Err(_) => match File::create_new(&at) {
                Ok(_) => {
                    return match fs::rename(part, &at) {
                        Ok(()) => Ok(at),
                        Err(error) => {
                            let _ = fs::remove_file(&at);
                            Err(failed(&at, &error))
                        }
                    };
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(failed(&at, &error)),
            },
        }
        if same(&at, offer).await {
            return Ok(at);
        }
    }
    Err(Error::new(format!(
        "{}: {PLACES} files of other bytes by that name and numbered",
        to.display()
    )))
}

/// Whether `error` is a range of the blob whose bytes do not match its
/// hash (iroh-blobs verifies each as it comes).
fn mismatch(error: &GetError) -> bool {
    matches!(
        error,
        GetError::Decode {
            source: DecodeError::LeafHashMismatch { .. } | DecodeError::ParentHashMismatch { .. },
            ..
        }
    )
}

/// Fetches the blob of `offer` from the peer at the end of `link` into a
/// store of its blob in `cache` (going on with what a fetch cut short
/// left there), no more of it than the offer's size, then opens it into
/// `to`, or beside it if another file is there ([`place`]). The store is
/// dropped once the file is whole or the blob refused; a fetch cut short
/// keeps it for the next.
async fn fetch_over(
    link: &Arc<dyn Link>,
    offer: &Offer,
    cache: &Fetches,
    to: &Path,
    progress: Option<&OnProgress>,
) -> Result<Fetched, Error> {
    fetches::destination(to, binbun_session::project::root().as_deref())?;
    let staged = cache.stage(offer.blob)?;
    let work = staged.store()?;
    let started = Instant::now();
    let store = loop {
        match FsStore::load(&work).await {
            Ok(store) => break store,
            Err(_) if started.elapsed() < STORE_WAIT => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(Error::new(format!("{}: {error}", work.display()))),
        }
    };
    let result = fetch_into(&store, link, offer, to, progress).await;
    let _ = store.shutdown().await;
    drop(store);
    match result {
        Ok(fetched) => {
            staged.remove();
            Ok(fetched)
        }
        Err(Failed::Refused(error)) => {
            staged.remove();
            Err(error)
        }
        Err(Failed::Cut(error)) => Err(error),
    }
}

/// [`fetch_over`] into `store`, open.
async fn fetch_into(
    store: &FsStore,
    link: &Arc<dyn Link>,
    offer: &Offer,
    to: &Path,
    progress: Option<&OnProgress>,
) -> Result<Fetched, Failed> {
    let hash = offer.hash();
    let total = offer.sealed();
    // The offer's size and no more: a larger blob is never asked for past
    // it, nor kept.
    let request =
        GetRequest::blob_ranges(hash, ChunkRanges::chunks(..total.div_ceil(BLAKE3_CHUNK)));
    let local = store
        .remote()
        .local_for_request(request)
        .await
        .map_err(|error| Failed::Cut(Error::new(error.to_string())))?;
    let had = local.local_bytes();
    let started = Instant::now();
    let received = if local.is_complete() {
        0
    } else {
        get_missing(store, link, offer, local.missing(), had, progress).await?
    };
    match store.blobs().status(hash).await {
        Ok(BlobStatus::Complete { size }) if size == total => {}
        Ok(_) => {
            return Err(Failed::Refused(Error::new(format!(
                "the {} from {} is refused: its blob is not the {total} bytes offered",
                offer.kind,
                link.remote()
            ))));
        }
        Err(error) => return Err(Failed::Cut(Error::new(error.to_string()))),
    }
    let fetching = started.elapsed();
    if let Some(progress) = progress {
        progress(&Progress {
            step: Step::Fetching,
            done: total,
            total,
        });
    }
    let opened = Instant::now();
    let (path, crypto) = open_into(store, offer, to, progress).await?;
    Ok(Fetched {
        path,
        sha256: offer.sha256,
        length: offer.length,
        sealed: total,
        had,
        received,
        fetching,
        opening: opened.elapsed(),
        crypto,
    })
}

/// A blob stream as iroh-blobs' get protocol runs over it.
pub(crate) type GetPair =
    iroh_blobs::get::StreamPair<AsyncReadRecvStream<Reader>, AsyncWriteSendStream<Writer>>;

/// Asks the peer at the end of `link` for blob `blob`: the stream to
/// fetch it over with iroh-blobs' get protocol, once it serves it.
pub(crate) async fn ask_blob(link: &Arc<dyn Link>, blob: BlobId) -> Result<GetPair, Error> {
    let (mut send, mut recv) = link.open(Lane::Blob).await?;
    write_frame(&mut *send, &BlobAsk::Get(blob)).await?;
    match read_frame::<BlobAnswer>(&mut *recv).await? {
        Some(BlobAnswer::Serving) => {}
        Some(BlobAnswer::Refused(why)) => return Err(Error::new(why.into_string())),
        Some(BlobAnswer::Offers { .. }) | None => {
            return Err(Error::new("the peer did not answer the ask for the blob"));
        }
    }
    Ok(iroh_blobs::get::StreamPair::new(
        0,
        AsyncReadRecvStream::new(Reader(Mutex::new(recv))),
        AsyncWriteSendStream::new(Writer(Mutex::new(send))),
    ))
}

/// Asks the peer at the end of `link` for the ranges of `offer`'s blob
/// `store` lacks (`missing`; `had` bytes here), each verified as it
/// comes: the bytes received. A byte past the offer's size refuses the
/// blob at once.
async fn get_missing(
    store: &FsStore,
    link: &Arc<dyn Link>,
    offer: &Offer,
    missing: GetRequest,
    had: u64,
    progress: Option<&OnProgress>,
) -> Result<u64, Failed> {
    let total = offer.sealed();
    let from = link.remote();
    let larger = || {
        Failed::Refused(Error::new(format!(
            "the {} from {from} is refused past byte {total}: larger than the {total} bytes \
             offered",
            offer.kind
        )))
    };
    let pair = ask_blob(link, offer.blob).await.map_err(Failed::Cut)?;
    let mut items = store.remote().execute_get(pair, missing).stream();
    let (mut received, mut told) = (0, Instant::now());
    while let Some(item) = items.next().await {
        match item {
            GetProgressItem::Progress(bytes) => {
                received = bytes;
                if had.saturating_add(bytes) > total {
                    return Err(larger());
                }
                if let Some(progress) = progress
                    && told.elapsed() >= TELL_EVERY
                {
                    told = Instant::now();
                    progress(&Progress {
                        step: Step::Fetching,
                        done: had + bytes,
                        total,
                    });
                }
            }
            GetProgressItem::Done(stats) => {
                return if had.saturating_add(stats.payload_bytes_read) > total {
                    Err(larger())
                } else {
                    Ok(stats.payload_bytes_read)
                };
            }
            GetProgressItem::Error(error) => {
                let kept = had + received;
                return Err(Failed::Cut(Error::new(if mismatch(&error) {
                    format!(
                        "the {} from {from} is refused past byte {kept} of {total}: a range does \
                         not match the blob's hash (tampered with, at the sender or on the way: \
                         {error}); the bytes verified before it are kept for the next fetch",
                        offer.kind
                    )
                } else {
                    format!(
                        "fetching the {} from {from} stopped after {kept} of {total} bytes: \
                         {error}; what was verified is kept for the next fetch",
                        offer.kind
                    )
                })));
            }
        }
    }
    Err(Failed::Cut(Error::new(format!(
        "fetching the {} from {from} stopped after {} of {total} bytes: the link ended; what \
         was verified is kept for the next fetch",
        offer.kind,
        had + received
    ))))
}

/// Opens the blob of `offer` in `store` into `to`: written beside it,
/// its SHA-256 checked, then placed ([`place`]). Where it is, and the
/// time the AEAD took.
async fn open_into(
    store: &FsStore,
    offer: &Offer,
    to: &Path,
    progress: Option<&OnProgress>,
) -> Result<(PathBuf, Duration), Failed> {
    let part = Part::beside(to).map_err(Failed::Cut)?;
    let written = |error: io::Error| Failed::Cut(failed(&part.path, &error));
    let read = |error: io::Error| Failed::Cut(Error::from(error));
    let mut reader = store.blobs().reader(offer.hash());
    let mut out = BufWriter::with_capacity(1 << 20, &part.file);
    let mut header = [0; HEADER];
    reader.read_exact(&mut header).await.map_err(read)?;
    let mut opener = Opener::new(&offer.key, offer.length, &header).map_err(Failed::Refused)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(blob::CHUNK + blob::TAG));
    let (mut done, mut told) = (0u64, Instant::now());
    while let Some(size) = opener.next_len() {
        buffer.clear();
        buffer.resize(size, 0);
        reader.read_exact(&mut buffer).await.map_err(read)?;
        let file = opener.open(&mut buffer).map_err(Failed::Refused)?;
        out.write_all(file).map_err(written)?;
        done += file.len() as u64;
        if let Some(progress) = progress
            && told.elapsed() >= TELL_EVERY
        {
            told = Instant::now();
            progress(&Progress {
                step: Step::Opening,
                done,
                total: offer.length,
            });
        }
    }
    let (sha256, crypto) = opener.finish().map_err(Failed::Refused)?;
    if sha256 != offer.sha256 {
        return Err(Failed::Refused(Error::new(format!(
            "the {} opened is not the one offered: its SHA-256 differs",
            offer.kind
        ))));
    }
    out.flush().map_err(written)?;
    out.get_ref().sync_all().map_err(written)?;
    drop(out);
    let path = place(&part.path, to, offer).await.map_err(Failed::Cut)?;
    if let Some(progress) = progress {
        progress(&Progress {
            step: Step::Opening,
            done: offer.length,
            total: offer.length,
        });
    }
    Ok((path, crypto))
}

/// The SHA-256 and length of the file at `path`, read on a blocking
/// thread.
async fn digest(path: PathBuf) -> Result<([u8; 32], u64), Error> {
    tokio::task::spawn_blocking(move || {
        let mut file = File::open(&path).map_err(|error| failed(&path, &error))?;
        let mut sha = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buffer = vec![0; 1 << 20];
        let mut length = 0;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| failed(&path, &error))?;
            let Some(read_bytes) = buffer.get(..read).filter(|bytes| !bytes.is_empty()) else {
                break;
            };
            sha.update(read_bytes);
            length += read as u64;
        }
        let mut sha256 = [0; 32];
        sha256.copy_from_slice(sha.finish().as_ref());
        Ok((sha256, length))
    })
    .await
    .map_err(|error| Error::new(error.to_string()))?
}

/// A blob's bytes as they are sealed, sent to the store.
struct Chunks(tokio::sync::mpsc::Sender<io::Result<Bytes>>);

impl Write for Chunks {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .blocking_send(Ok(Bytes::copy_from_slice(bytes)))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the store stopped"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What sealing a file into the store came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    /// The offer.
    pub offer: Offer,
    /// Whether the blob was kept from before (else sealed now).
    pub kept: bool,
    /// The time sealing took (none if kept).
    pub sealing: Duration,
    /// Of that, the time the AEAD took.
    pub crypto: Duration,
}

impl Inner {
    /// The cipher of the offers this peer keeps.
    fn kept_cipher(&self) -> chacha20poly1305::XChaCha20Poly1305 {
        crypto::local(&self.secret, self.state().membership.project(), OFFERS)
    }

    /// The offers kept beside the store (none if no file).
    fn kept(&self) -> Result<Vec<Offer>, Error> {
        let path = self.blobs.dir()?.join("blobs").join("offers.bin");
        let sealed = match fs::read(&path) {
            Ok(sealed) => sealed,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(failed(&path, &error)),
        };
        let plain = crypto::open_bare(&self.kept_cipher(), &sealed).ok_or_else(|| {
            Error::new(format!(
                "{}: does not open (another identity's?)",
                path.display()
            ))
        })?;
        decode_offers(&plain).map_err(|error| Error::new(format!("{}: {error}", path.display())))
    }

    /// Keeps `offers` beside the store, in place of those kept.
    fn keep(&self, offers: &[Offer]) -> Result<(), Error> {
        let dir = self.blobs.dir()?.join("blobs");
        let plain = Zeroizing::new(encode_offers(offers)?);
        let sealed = crypto::seal_bare(&self.kept_cipher(), &plain)?;
        let temporary = dir.join("offers.bin.tmp");
        fs::write(&temporary, sealed).map_err(|error| failed(&temporary, &error))?;
        fs::rename(&temporary, dir.join("offers.bin")).map_err(|error| failed(&dir, &error))
    }

    /// Offers the session's file of `kind`: the blob kept from before if
    /// it is of the same file, else the file sealed into the store now.
    pub(crate) async fn offer(&self, kind: Kind) -> Result<Prepared, Error> {
        let session = self.session();
        let path = match kind {
            Kind::Binary => session.path().to_path_buf(),
            Kind::DebugFile => session
                .debug_file()
                .ok_or_else(|| Error::new("the analysis read no debug file"))?
                .to_path_buf(),
        };
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        // The binary's hash is the session's file's (sealing checks the
        // file still has it); a debug file's is read. A universal binary
        // goes whole, naming the slice shared.
        let known = (kind == Kind::Binary)
            .then(|| {
                let sha256 = session.file_sha256()?;
                Some((sha256, session.bytes()?.len() as u64))
            })
            .flatten();
        let arch = (kind == Kind::Binary)
            .then(|| session.slice().map(Text::truncated))
            .flatten();
        let (sha256, length) = match known {
            Some(known) => known,
            None => digest(path.clone()).await?,
        };
        let store = self.blobs.store().await?;
        let mut kept = self.kept()?;
        let reuse = kept
            .iter()
            .find(|offer| offer.kind == kind && offer.sha256 == sha256 && offer.length == length)
            .cloned()
            .map(|offer| Offer {
                arch: arch.clone(),
                ..offer
            });
        let complete = match &reuse {
            Some(offer) => matches!(
                store.blobs().status(offer.hash()).await,
                Ok(BlobStatus::Complete { size }) if size == offer.sealed()
            ),
            None => false,
        };
        let prepared = match reuse.filter(|_| complete) {
            Some(offer) => Prepared {
                offer,
                kept: true,
                sealing: Duration::ZERO,
                crypto: Duration::ZERO,
            },
            None => seal_into(&store, path, kind, name, (sha256, length), arch).await?,
        };
        for old in kept
            .iter()
            .filter(|old| old.kind == kind && old.blob != prepared.offer.blob)
        {
            let _ = store.tags().delete(tag(old.blob)).await;
        }
        kept.retain(|old| old.kind != kind);
        kept.push(prepared.offer.clone());
        self.keep(&kept)?;
        {
            let mut offered = self
                .blobs
                .offered
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            offered.retain(|old| old.kind != kind);
            offered.push(prepared.offer.clone());
        }
        Ok(prepared)
    }

    /// Serves one blob stream `remote` opened on link `link`: its offers,
    /// or the blob it asks for if offered, holding `stream`'s places
    /// throughout. The ask is read within its frame's limit
    /// ([`wire::BLOB_ASK_FRAME`]), reserved before it is read, by the
    /// stream's deadline ([`Stream::ask_by`]). Rights are those of the
    /// link and the chain when the ask is read, and again before each
    /// mebibyte of a blob ([`Inner::serving`], sync §3.6): before the
    /// link's sync is a reader's, only the offer of the binary the
    /// membership chain names and that blob are served; a link revoked or
    /// a member removed, nothing.
    pub(crate) async fn serve_blob(
        self: Arc<Self>,
        remote: PublicKey,
        link: LinkId,
        stream: Stream,
        mut send: SendStream,
        mut recv: RecvStream,
    ) {
        let asked = async {
            let Some(length) = read_frame_length(&mut *recv, BlobAsk::LIMIT).await? else {
                return Ok(None);
            };
            let Some(_frame) = self.budgets.frame(length).await else {
                return Err(Error::new("an ask past the frames' ceiling"));
            };
            read_frame_body::<BlobAsk>(&mut *recv, length)
                .await
                .map(Some)
        };
        let Ok(Ok(Some(ask))) = stream.ask_by().within(asked).await else {
            return;
        };
        let Some(phase) = self.serving(remote, link) else {
            let refused = BlobAnswer::Refused(Text::truncated("not a member of this project"));
            let _ = write_frame(&mut *send, &refused).await;
            return;
        };
        let home = self.home_offer();
        if phase != Phase::Reader {
            let allowed = match &ask {
                BlobAsk::Home => true,
                BlobAsk::Get(blob) => home.as_ref().is_some_and(|offer| offer.blob == *blob),
                BlobAsk::Offers => false,
            };
            if !allowed {
                let refused = BlobAnswer::Refused(Text::truncated(
                    "only the binary shared is served before the link syncs",
                ));
                let _ = write_frame(&mut *send, &refused).await;
                return;
            }
        }
        match ask {
            BlobAsk::Offers | BlobAsk::Home => {
                let offers = match ask {
                    BlobAsk::Home => home.into_iter().collect(),
                    BlobAsk::Offers | BlobAsk::Get(_) => self.blobs.offered(),
                };
                let answer = {
                    let state = self.state();
                    let project = state.membership.project();
                    match (state.membership.genesis(), state.keys.last_key_value()) {
                        (Some(genesis), Some((epoch, key))) => {
                            seal_offers(key, project, &genesis, *epoch, &offers)
                                .map(|(epoch, sealed)| BlobAnswer::Offers { epoch, sealed })
                        }
                        _ => Ok(BlobAnswer::Refused(Text::truncated(
                            "this peer holds no key",
                        ))),
                    }
                };
                match answer {
                    Ok(answer) => {
                        let _ = write_frame(&mut *send, &answer).await;
                    }
                    Err(error) => self.tell(&Notice::Failed(error.to_string())),
                }
            }
            BlobAsk::Get(blob) => self.serve_get(remote, link, blob, send, recv).await,
        }
    }

    /// The offer of the binary the membership chain names, if this peer
    /// offers that file.
    fn home_offer(&self) -> Option<Offer> {
        let sha256 = {
            let state = self.state();
            state.membership.binary(&state.keys)?.sha256
        };
        self.blobs
            .offered()
            .into_iter()
            .find(|offer| offer.kind == Kind::Binary && offer.sha256 == sha256)
    }

    /// Serves blob `blob` to `remote` on its stream on link `link`, if
    /// offered: before each mebibyte, only while `remote` may still be
    /// served on it.
    async fn serve_get(
        self: &Arc<Self>,
        remote: PublicKey,
        link: LinkId,
        blob: BlobId,
        mut send: SendStream,
        recv: RecvStream,
    ) {
        let Some(offer) = self.blobs.offer_of(blob) else {
            let refused = BlobAnswer::Refused(Text::truncated("that blob is not offered"));
            let _ = write_frame(&mut *send, &refused).await;
            return;
        };
        let store = match self.blobs.store().await {
            Ok(store) => store,
            Err(error) => {
                let refused = BlobAnswer::Refused(Text::truncated(&error.to_string()));
                let _ = write_frame(&mut *send, &refused).await;
                return;
            }
        };
        if write_frame(&mut *send, &BlobAnswer::Serving).await.is_err() {
            return;
        }
        self.tell(&Notice::Sending {
            to: remote,
            kind: offer.kind,
            name: offer.name.to_string(),
        });
        let inner = Arc::clone(self);
        let fenced = Fenced {
            send,
            serving: Box::new(move || inner.serving(remote, link).is_some()),
            left: 0,
        };
        let result = provide(&store, offer.hash(), Box::new(fenced), recv).await;
        self.tell(&Notice::Sent {
            to: remote,
            kind: offer.kind,
            name: offer.name.into_string(),
            error: result.err(),
        });
    }

    /// The link to `from`, if up.
    fn link_to(&self, from: PublicKey) -> Result<Arc<dyn Link>, Error> {
        self.state()
            .links
            .get(&from)
            .map(|link| Arc::clone(&link.link))
            .ok_or_else(|| Error::new(format!("no link to {from}")))
    }

    /// The key of epoch `epoch`, if held, waiting for it while `link` is
    /// up ([`KEY_WAIT`] at most) unless the membership chain is past that
    /// epoch (a key comes with its epoch's records): an answer on `link`
    /// sealed in an epoch whose key it is bringing may come first.
    pub(crate) async fn epoch_key(&self, epoch: u32, link: &Arc<dyn Link>) -> Option<EpochKey> {
        let mut taken = self.keyed.subscribe();
        let arrived = async {
            loop {
                {
                    let state = self.state();
                    if let Some(key) = state.keys.get(&epoch) {
                        return Some(key.clone());
                    }
                    if epoch < state.membership.epoch() {
                        return None;
                    }
                }
                if taken.changed().await.is_err() {
                    return None;
                }
            }
        };
        tokio::select! {
            key = tokio::time::timeout(KEY_WAIT, arrived) => key.ok().flatten(),
            () = link.closed() => self.state().keys.get(&epoch).cloned(),
        }
    }
}

/// Serves blob `hash` from `store` on a stream (`send`, `recv`) whose ask
/// was answered [`BlobAnswer::Serving`]: iroh-blobs' get protocol, for
/// that blob only (a request for another is refused). Why it stopped, if
/// it did.
pub(crate) async fn provide(
    store: &FsStore,
    hash: Hash,
    send: SendStream,
    recv: RecvStream,
) -> Result<(), String> {
    let (events, mut asked) = EventSender::channel(
        4,
        EventMask {
            get: RequestMode::Intercept,
            get_many: RequestMode::Disabled,
            push: RequestMode::Disabled,
            observe: ObserveMode::Disabled,
            ..EventMask::DEFAULT
        },
    );
    // Only the blob asked for: a request for another is refused.
    let guard = tokio::spawn(async move {
        while let Some(message) = asked.recv().await {
            if let ProviderMessage::GetRequestReceived(message) = message {
                let verdict = if message.inner.request.hash == hash {
                    Ok(())
                } else {
                    Err(AbortReason::Permission)
                };
                let _ = message.tx.send(verdict).await;
            }
        }
    });
    let pair = iroh_blobs::provider::StreamPair::new(
        0,
        AsyncReadRecvStream::new(Reader(Mutex::new(recv))),
        AsyncWriteSendStream::new(Writer(Mutex::new(send))),
        events,
    );
    let result = iroh_blobs::provider::handle_stream(pair, (**store).clone()).await;
    guard.abort();
    result.map_err(|error| error.to_string())
}

/// The store's tag keeping blob `blob`.
fn tag(blob: BlobId) -> String {
    format!("binbun/{}", Hash::from_bytes(blob.0).to_hex())
}

/// Seals the file at `path` (of `kind`, named `name`, its SHA-256 and
/// length known; a universal binary's slice shared, `arch`) into `store`
/// under a new key: its offer.
async fn seal_into(
    store: &FsStore,
    path: PathBuf,
    kind: Kind,
    name: String,
    (sha256, length): ([u8; 32], u64),
    arch: Option<Text<MAX_ARCH>>,
) -> Result<Prepared, Error> {
    let key = BlobKey::random()?;
    let started = Instant::now();
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<io::Result<Bytes>>(64);
    let sealing = {
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            let file = File::open(&path).map_err(|error| failed(&path, &error))?;
            let mut reader = io::BufReader::with_capacity(1 << 20, file);
            let mut chunks = Chunks(sender.clone());
            let sealed = blob::seal(&key, None, length, &mut reader, &mut chunks);
            if let Err(error) = &sealed {
                let _ = sender.blocking_send(Err(io::Error::other(error.to_string())));
            }
            sealed
        })
    };
    let stream = n0_future::stream::poll_fn(move |cx| receiver.poll_recv(cx));
    let added = store.blobs().add_stream(stream).await.temp_tag().await;
    let sealed: Result<blob::Sealed, Error> = sealing
        .await
        .map_err(|error| Error::new(error.to_string()))?;
    let sealed = sealed?;
    let added =
        added.map_err(|error| Error::new(format!("the store did not take the blob: {error}")))?;
    if sealed.sha256 != sha256 {
        return Err(Error::new(
            "the file is not the one analysed (its SHA-256 differs): open it again to send it",
        ));
    }
    let blob = BlobId(*added.hash().as_bytes());
    store
        .tags()
        .set(tag(blob), HashAndFormat::raw(added.hash()))
        .await
        .map_err(|error| Error::new(error.to_string()))?;
    Ok(Prepared {
        offer: Offer {
            blob,
            key,
            length,
            sha256,
            kind,
            name: Text::truncated(&name),
            arch,
        },
        kept: false,
        sealing: started.elapsed(),
        crypto: sealed.crypto,
    })
}

impl Peer {
    /// Offers the session's file of `kind` (its binary, or the debug file
    /// its analysis read) to the members linked, who may fetch it
    /// ([`Self::fetch`]): sealed into the store beside the project, or the
    /// blob sealed before if it is of the same file. What the sharer
    /// chose to send: nothing is offered unless asked.
    ///
    /// # Errors
    ///
    /// No such file (no debug file read), it cannot be read or changed
    /// since it was opened; the session has no project; the store fails.
    pub async fn offer(&self, kind: Kind) -> Result<Prepared, Error> {
        self.inner().offer(kind).await
    }

    /// Offers the file of `kind` no longer (its blob kept, to offer again).
    pub fn withdraw(&self, kind: Kind) {
        self.inner()
            .blobs
            .offered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|offer| offer.kind != kind);
    }

    /// What this peer offers now.
    pub fn offered(&self) -> Vec<Offer> {
        self.inner().blobs.offered()
    }

    /// What member `from`, linked, offers. A list that does not open is
    /// told ([`Notice::Failed`]), and nothing listed.
    ///
    /// # Errors
    ///
    /// No link to them; no membership chain held yet; the offers do not
    /// come.
    pub async fn offers(&self, from: PublicKey) -> Result<Vec<Offer>, Error> {
        let inner = self.inner();
        let link = inner.link_to(from)?;
        let (project, genesis) = {
            let state = inner.state();
            (state.membership.project(), state.membership.genesis())
        };
        let genesis = genesis.ok_or_else(|| Error::new("no membership chain held yet"))?;
        let (epoch, sealed) = ask_offers(&link, &BlobAsk::Offers).await?;
        let key = inner.epoch_key(epoch, &link).await;
        Ok(
            open_offers(project, &genesis, epoch, &sealed, key).unwrap_or_else(|error| {
                inner.tell(&Notice::Failed(skipped(from, &error)));
                Vec::new()
            }),
        )
    }

    /// Fetches the file `offer` (one of member `from`'s, linked) into
    /// `to`, going on with what a fetch of it cut short left in
    /// `cache`. A file of other bytes at `to` stays: the one fetched
    /// goes beside it ([`Fetched::path`]).
    ///
    /// # Errors
    ///
    /// No link to them; `to` is in binbun's projects folder; another
    /// fetch of it is under way; they serve it no longer; a range of it
    /// does not match its hash (nothing past it is kept); its blob is
    /// larger than offered, or of another size; a chunk does not open, or
    /// the file is not the one offered (these three keep nothing of it);
    /// a file cannot be written.
    pub async fn fetch(
        &self,
        from: PublicKey,
        offer: &Offer,
        cache: &Fetches,
        to: &Path,
        progress: Option<OnProgress>,
    ) -> Result<Fetched, Error> {
        let link = self.inner().link_to(from)?;
        fetch_over(&link, offer, cache, to, progress.as_ref()).await
    }
}

/// A visit to a host by one who has not joined yet (no session to join
/// with, or not yet in the share's own project): let in as a join is (a
/// key the owner added at once; with live approval, a ticket holder once
/// approved), takes the membership chain for the share's genesis and the
/// epoch's key, staying in Bootstrap (sync §3.6), and may then fetch the
/// binary the chain names if the host offers it: nothing else is served
/// before a link syncs. Joining afterwards lets the member in at once.
pub struct Visit {
    link: Arc<dyn Link>,
    project: ProjectId,
    keys: BTreeMap<u32, EpochKey>,
    /// The binary the owner's chain names, if its key opens it.
    binary: Option<Binary>,
    /// The share's genesis: the hash of its first record.
    genesis: [u8; 32],
    /// Hears what the visit tells (`config`'s).
    notify: Option<Notifier>,
    /// Keeps the sync and control lanes open while the visit lasts.
    lanes: JoinHandle<()>,
}

impl fmt::Debug for Visit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Visit")
            .field("host", &self.link.remote())
            .finish_non_exhaustive()
    }
}

/// How long a visit waits for the host's membership chain once admitted.
const CHAIN_WAIT: Duration = Duration::from_secs(30);

/// Tells `notice` to `notify`, if any.
fn tell(notify: Option<&Notifier>, notice: &Notice) {
    if let Some(notify) = notify {
        notify(notice);
    }
}

/// Writes `message` on a sync lane, `to`.
async fn say(to: &mut SendStream, message: &Said) -> Result<(), Error> {
    write_bytes(&mut **to, &message.encode()?).await
}

/// Asks for the records past `membership`'s head on a sync lane
/// (`to`), as request `id`.
async fn ask_records(to: &mut SendStream, id: u32, membership: &Membership) -> Result<(), Error> {
    let (after, at) = membership.head();
    say(to, &Said::RecordsAsk { id, after, at }).await
}

/// Takes the membership chain over a sync lane in Bootstrap (`lane`)
/// into `membership` until it reaches the head the host told and holds
/// a key `identity` holds for the epoch now (`keys`): this side's head
/// told, the records past it asked for in pages. Nothing that names a
/// chain is asked or told.
///
/// # Errors
///
/// The lane fails or ends; a record does not verify; the host's chain
/// is another.
async fn take_chain(
    lane: (&mut SendStream, &mut RecvStream),
    identity: &Identity,
    membership: &mut Membership,
    keys: &mut BTreeMap<u32, EpochKey>,
) -> Result<(), Error> {
    let (send, recv) = lane;
    let me = identity.public();
    let secret = Zeroizing::new(identity.agreement_secret());
    let project = membership.project();
    say(
        send,
        &Said::MembershipHead {
            membership: membership.head(),
        },
    )
    .await?;
    let mut theirs = None;
    let mut asked = 0u32;
    loop {
        if theirs.is_some_and(|(seq, _)| seq <= membership.seq())
            && keys.contains_key(&membership.epoch())
        {
            return Ok(());
        }
        let Some(length) = read_frame_length(&mut **recv, BOOTSTRAP_FRAME).await? else {
            return Err(Error::new("the host closed the sync lane"));
        };
        let message = Said::decode(&read_bytes(&mut **recv, length).await?)?;
        if let Said::MembershipHead { membership: head } = message {
            theirs = Some(head);
            if head.0 > membership.seq() {
                asked += 1;
                ask_records(send, asked, membership).await?;
            }
        } else if let Said::Records { records, more, .. } = message {
            for bytes in &records {
                let signed: SignedRecord = bounded::decode(bytes)?;
                let record = membership.take(&signed)?;
                for (member, wrapped) in &record.wraps {
                    if *member == me {
                        let key = crypto::unwrap(wrapped, project, record.epoch, me, &secret)?;
                        keys.insert(record.epoch, key);
                    }
                }
            }
            if more {
                asked += 1;
                ask_records(send, asked, membership).await?;
            }
        } else if let Said::RecordsDiverged { .. } = message {
            return Err(Error::new(
                "the host's membership chain is not the one this ticket's owner began",
            ));
        }
    }
}

/// One dial of `ticket`'s host over `transport` as `config`'s identity,
/// saying the head of `membership`: the link and its control lane once
/// welcomed. Put out, the kick's records are taken into `membership`;
/// `None` if they stop short of more that follow, for a dial again from
/// the head they leave.
///
/// # Errors
///
/// The host cannot be reached or refuses; it puts this peer out, its
/// records then taken as far as they verify (through its removal, it
/// says which record).
async fn welcomed(
    transport: &Arc<dyn Transport>,
    config: &Config,
    ticket: &JoinTicket,
    membership: &mut Membership,
) -> Result<Option<(Arc<dyn Link>, SendStream, RecvStream)>, Error> {
    let link = transport.connect(&ticket.host).await?;
    if link.remote() != ticket.host.id {
        link.close("not the host");
        return Err(Error::new("the host's key is not the ticket's"));
    }
    let (mut control_send, mut control_recv) = link.open(Lane::Control).await?;
    let hello = Control::Hello(Box::new(Hello {
        protocol: PROTOCOL,
        log: LOG,
        engine: Engine::of(&config.engine),
        project: ticket.project,
        invite: Some(ticket.invite),
        card: Card::new(&config.identity, &config.name),
        membership: membership.head(),
        features: FEATURES,
    }));
    write_frame(&mut *control_send, &hello).await?;
    loop {
        match read_frame::<Answer>(&mut *control_recv)
            .await?
            .map(|Answer(answer)| answer)
        {
            Some(Control::Pending) => tell(config.notify.as_ref(), &Notice::Waiting),
            Some(Control::Welcome { .. }) => return Ok(Some((link, control_send, control_recv))),
            Some(Control::Denied { reason }) => {
                link.close("denied");
                return Err(Error::new(format!("denied: {reason}")));
            }
            Some(Control::Kick { reason, records }) => {
                link.close("kicked");
                let before = membership.seq();
                let taken = records
                    .items
                    .iter()
                    .take_while(|signed| membership.take(signed).is_ok())
                    .count();
                if let Some(removal) = membership.removal(config.identity.public()) {
                    return Err(Error::new(format!(
                        "put out: removed from the project by its owner, as its membership \
                         record {removal} says"
                    )));
                }
                if records.more && taken == records.items.len() && membership.seq() > before {
                    return Ok(None);
                }
                return Err(Error::new(format!("put out: {reason}")));
            }
            Some(Control::Hello(_)) | None => {
                link.close("no answer");
                return Err(Error::new("the host did not answer"));
            }
        }
    }
}

impl Visit {
    /// Visits the host of `ticket` over `transport` as `config`'s
    /// identity (its notices told: waiting for approval, denied). Put
    /// out, it takes the records of its removal and says so.
    ///
    /// # Errors
    ///
    /// The host cannot be reached, refuses or puts this peer out, or
    /// sends no chain with a key for this peer.
    pub async fn new(
        transport: &Arc<dyn Transport>,
        config: &Config,
        ticket: &JoinTicket,
    ) -> Result<Self, Error> {
        let notify = config.notify.clone();
        let project = ticket.project;
        let mut membership = Membership::expecting(project, ticket.owner);
        // Put out, the records saying so come a page a dial, from the
        // head the visit holds: taken while they come.
        let (link, control_send, control_recv) = loop {
            if let Some(welcomed) = welcomed(transport, config, ticket, &mut membership).await? {
                break welcomed;
            }
        };
        let (mut sync_send, mut sync_recv) = link.open(Lane::Sync).await?;
        let mut keys = BTreeMap::new();
        let chain = take_chain(
            (&mut sync_send, &mut sync_recv),
            &config.identity,
            &mut membership,
            &mut keys,
        );
        match tokio::time::timeout(CHAIN_WAIT, chain).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                link.close("no chain");
                return Err(error);
            }
            Err(_) => {
                link.close("no chain");
                return Err(Error::new(
                    "the host sent no membership chain with a key for this peer",
                ));
            }
        }
        // The lanes stay open, what comes on them unread, while the visit
        // lasts.
        let lanes = tokio::spawn(async move {
            let _held = (control_send, control_recv, sync_send);
            while let Ok(Some(length)) = read_frame_length(&mut *sync_recv, BOOTSTRAP_FRAME).await {
                if read_bytes(&mut *sync_recv, length).await.is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            link,
            project,
            binary: membership.binary(&keys),
            genesis: membership.genesis().unwrap_or_default(),
            keys,
            notify,
            lanes,
        })
    }

    /// The share's genesis: the hash of its first membership record, which
    /// names a joiner's project for it
    /// (`binbun_session::project::Key::share_dir_name`).
    pub fn genesis(&self) -> [u8; 32] {
        self.genesis
    }

    /// The binary the shared project annotates, as its owner's membership
    /// chain names it: `None` if the key of the epoch that sealed it does
    /// not open it.
    pub fn binary(&self) -> Option<&Binary> {
        self.binary.as_ref()
    }

    /// What the host offers. A list that does not open is told
    /// ([`Notice::Failed`]), and nothing listed.
    ///
    /// # Errors
    ///
    /// The offers do not come.
    pub async fn offers(&self) -> Result<Vec<Offer>, Error> {
        let from = self.link.remote();
        let (epoch, sealed) = ask_offers(&self.link, &BlobAsk::Home).await?;
        let key = self.keys.get(&epoch).cloned();
        Ok(
            open_offers(self.project, &self.genesis, epoch, &sealed, key).unwrap_or_else(|error| {
                tell(self.notify.as_ref(), &Notice::Failed(skipped(from, &error)));
                Vec::new()
            }),
        )
    }

    /// Fetches the file `offer` from the host into `to`, the blob kept in
    /// `cache` until the file is whole (a fetch cut short goes on from
    /// there; a blob refused is dropped). A file of other bytes at `to`
    /// stays: the one fetched goes beside it ([`Fetched::path`]).
    ///
    /// # Errors
    ///
    /// As [`Peer::fetch`].
    pub async fn fetch(
        &self,
        offer: &Offer,
        cache: &Fetches,
        to: &Path,
        progress: Option<OnProgress>,
    ) -> Result<Fetched, Error> {
        fetch_over(&self.link, offer, cache, to, progress.as_ref()).await
    }

    /// Ends the visit.
    pub fn close(self) {
        self.lanes.abort();
        self.link.close("visited");
    }
}

#[cfg(test)]
mod tests {
    use binbun_bounded::Text;
    use binbun_session::journal::{BlobId, ProjectId};

    use super::{Kind, MAX_OFFERS, Offer, decode_offers, encode_offers, open_offers, seal_offers};
    use crate::blob::BlobKey;
    use crate::crypto::EpochKey;

    fn offer(kind: Kind, name: &str, arch: Option<&str>) -> Offer {
        Offer {
            blob: BlobId([u8::from(kind == Kind::Binary); 32]),
            key: BlobKey::random().unwrap(),
            length: 4096,
            sha256: [7; 32],
            kind,
            name: Text::truncated(name),
            arch: arch.map(Text::truncated),
        }
    }

    #[test]
    fn offers_with_and_without_a_slice_read_back() {
        let plain = vec![offer(Kind::DebugFile, "bash.debug", None)];
        let bytes = encode_offers(&plain).unwrap();
        assert_eq!(bytes, postcard::to_allocvec(&plain).unwrap());
        assert_eq!(decode_offers(&bytes).unwrap(), plain);

        let sliced = vec![
            offer(Kind::Binary, "tool", Some("arm64e")),
            offer(Kind::DebugFile, "tool.dSYM", None),
        ];
        let bytes = encode_offers(&sliced).unwrap();
        let read = decode_offers(&bytes).unwrap();
        assert_eq!(read, sliced);
        assert_eq!(read[0].arch.as_deref(), Some("arm64e"));
        // Bytes past the offers are refused.
        let mut longer = bytes;
        longer.push(0);
        assert!(decode_offers(&longer).is_err());
        // A list past the bound is refused, and none is sent.
        let many = vec![offer(Kind::DebugFile, "a", None); MAX_OFFERS + 1];
        assert!(decode_offers(&postcard::to_allocvec(&many).unwrap()).is_err());
        assert!(encode_offers(&many).is_err());
    }

    #[test]
    fn offers_sealed_in_one_share_are_refused_in_another_of_its_routing_id() {
        // A home log shared twice: one routing id, the same key here, two
        // geneses.
        let project = ProjectId([3; 16]);
        let (genesis, other) = ([0x47; 32], [0x48; 32]);
        let key = EpochKey::random().unwrap();
        let offers = vec![offer(Kind::DebugFile, "bash.debug", None)];
        let (epoch, sealed) = seal_offers(&key, project, &genesis, 2, &offers).unwrap();
        let open = |genesis: &[u8; 32], epoch: u32| {
            open_offers(project, genesis, epoch, &sealed, Some(key.clone()))
        };
        assert_eq!(open(&genesis, epoch).unwrap(), offers);
        assert!(open(&other, epoch).is_err());
        // Nor in another epoch of its own share under that key.
        assert!(open(&genesis, epoch + 1).is_err());
    }
}
