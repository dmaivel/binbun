//! A file sealed as a blob: the binary or a debug file, encrypted under a
//! key of its own (a
//! [`BlobKey`]: 32 random bytes, sent to members inside a sealed offer,
//! so a new epoch never seals a 1 GB binary again), in the STREAM
//! construction (Hoang, Reyhanitabar, Rogaway, Vizár 2015) as age's
//! payload uses it:
//!
//! ```text
//! blob   = "binbun-blob\x01" ‖ chunk:u32be (65536) ‖ prefix:19 ‖ chunk₀ ‖ … ‖ chunkₙ₋₁
//! chunkᵢ = XChaCha20-Poly1305(plaintextᵢ, nonce = prefix ‖ i:u32be ‖ last:u8, aad = the 35-byte header)
//! ```
//!
//! The plaintext is the file padded with zeros to its Padmé length
//! ([`padme`]; Nikitin et al., Privacy Enhancing Technologies 2019): at
//! most 12 % more, and the
//! length a blob shows tells little of the file's. It is cut into chunks
//! of 64 KiB, the last shorter (or empty, for an empty file); `last` is 1
//! in the last chunk's nonce only, so a blob cut short, grown, or with its
//! chunks reordered does not open. A blob's size is a function of the
//! Padmé length alone ([`sealed_len`]): 35 bytes of header and 16 of tag
//! per chunk past it.
//!
//! The same key and prefix seal the same file to the same bytes: a host
//! keeps both with the blob, so the blob, and its id, stay the same.

use std::fmt;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Error;
use crate::crypto;

/// What a blob starts with.
pub const MAGIC: &[u8; 12] = b"binbun-blob\x01";

/// The bytes of plaintext in each chunk but the last.
pub const CHUNK: usize = 1 << 16;

/// The bytes of the nonce prefix.
const PREFIX: usize = 19;

/// The bytes of a blob before its first chunk.
pub const HEADER: usize = MAGIC.len() + 4 + PREFIX;

/// The bytes of a chunk's tag.
pub const TAG: usize = 16;

/// [`CHUNK`] as a `u64`.
const CHUNK_U64: u64 = 1 << 16;

/// `length` padded to its Padmé length: the low `⌊log₂ E⌋ + 1` bits of
/// its `E = ⌊log₂ length⌋`-bit magnitude kept, the rest rounded up; so a
/// length shows `O(log log length)` bits, for at most 12 % more bytes.
/// A length that rounds past [`u64::MAX`] (an offer's, not a file's) pads
/// to it.
pub fn padme(length: u64) -> u64 {
    if length < 2 {
        return length;
    }
    let exponent = length.ilog2();
    let kept = exponent.ilog2() + 1;
    let mask = (1u64 << (exponent - kept)) - 1;
    length.checked_add(mask).map_or(u64::MAX, |up| up & !mask)
}

/// The chunks of `padded` bytes of plaintext: one at least.
fn chunks(padded: u64) -> u64 {
    padded.div_ceil(CHUNK_U64).max(1)
}

/// The size of the blob sealing a file of `length` bytes: a function of
/// its Padmé length alone ([`u64::MAX`] at most).
pub fn sealed_len(length: u64) -> u64 {
    let padded = padme(length);
    (HEADER as u64)
        .saturating_add(padded)
        .saturating_add(TAG as u64 * chunks(padded))
}

/// A blob's own key.
#[derive(Clone, PartialEq, Eq)]
pub struct BlobKey(Zeroizing<[u8; 32]>);

impl Serialize for BlobKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BlobKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <[u8; 32]>::deserialize(deserializer).map(|key| Self(Zeroizing::new(key)))
    }
}

impl fmt::Debug for BlobKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlobKey(..)")
    }
}

impl BlobKey {
    /// A new one.
    ///
    /// # Errors
    ///
    /// The system has no randomness.
    pub fn random() -> Result<Self, Error> {
        Ok(Self(Zeroizing::new(crypto::random()?)))
    }

    /// Its cipher.
    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&Key::from(*self.0))
    }
}

/// What sealing a file came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// The file's SHA-256.
    pub sha256: [u8; 32],
    /// Its bytes.
    pub length: u64,
    /// The blob's bytes ([`sealed_len`] of the length).
    pub sealed: u64,
    /// The time spent encrypting (the AEAD alone).
    pub crypto: Duration,
}

/// A blob's header for `prefix`.
fn header(prefix: &[u8; PREFIX]) -> [u8; HEADER] {
    let mut header = [0; HEADER];
    let (magic, rest) = header.split_at_mut(MAGIC.len());
    magic.copy_from_slice(MAGIC);
    let (chunk, rest) = rest.split_at_mut(4);
    chunk.copy_from_slice(&u32::try_from(CHUNK).unwrap_or(u32::MAX).to_be_bytes());
    rest.copy_from_slice(prefix);
    header
}

/// Chunk `index`'s nonce under `prefix`.
fn nonce(prefix: &[u8], index: u32, last: bool) -> XNonce {
    let mut nonce = [0; 24];
    let (start, rest) = nonce.split_at_mut(PREFIX);
    start.copy_from_slice(prefix);
    let (counter, flag) = rest.split_at_mut(4);
    counter.copy_from_slice(&index.to_be_bytes());
    if let Some(flag) = flag.first_mut() {
        *flag = u8::from(last);
    }
    XNonce::from(nonce)
}

/// Reads into `buffer` until it is full or `from` ends: the bytes read.
fn fill(from: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut read = 0;
    while let Some(rest) = buffer.get_mut(read..) {
        if rest.is_empty() {
            break;
        }
        match from.read(rest) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(read)
}

/// The file of `length` bytes read from `from` sealed under `key` with a
/// random nonce prefix, the blob written to `to` in pieces of at most a
/// chunk and its tag; what it came to.
///
/// # Errors
///
/// `from` fails or holds other than `length` bytes; `to` fails; no
/// randomness.
pub fn seal(
    key: &BlobKey,
    prefix: Option<[u8; PREFIX]>,
    length: u64,
    from: &mut impl Read,
    to: &mut impl Write,
) -> Result<Sealed, Error> {
    let prefix = match prefix {
        Some(prefix) => prefix,
        None => crypto::random()?,
    };
    let cipher = key.cipher();
    let header = header(&prefix);
    to.write_all(&header)?;
    let padded = padme(length);
    let count = chunks(padded);
    let mut sha = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = Zeroizing::new(Vec::with_capacity(CHUNK + TAG));
    let (mut taken, mut crypto) = (0u64, Duration::ZERO);
    for index in 0..count {
        let start = index * CHUNK_U64;
        let size = usize::try_from((padded - start).min(CHUNK_U64)).unwrap_or(CHUNK);
        buffer.clear();
        buffer.resize(size, 0);
        let real = usize::try_from(length.saturating_sub(start).min(CHUNK_U64)).unwrap_or(CHUNK);
        let got = fill(from, buffer.get_mut(..real).unwrap_or_default())?;
        if got < real {
            return Err(Error::new(format!(
                "the file ended at byte {}, not {length}: it changed while it was sealed",
                taken + got as u64
            )));
        }
        taken += got as u64;
        sha.update(buffer.get(..real).unwrap_or_default());
        let last = index + 1 == count;
        let counter = u32::try_from(index).map_err(|_| Error::new("a file too large to seal"))?;
        let began = Instant::now();
        cipher
            .encrypt_in_place(&nonce(&prefix, counter, last), &header, &mut *buffer)
            .map_err(|_| Error::new("a chunk that does not seal"))?;
        crypto += began.elapsed();
        to.write_all(&buffer)?;
    }
    let mut more = [0; 1];
    if fill(from, &mut more)? != 0 {
        return Err(Error::new(format!(
            "the file is longer than {length} bytes: it changed while it was sealed"
        )));
    }
    let mut sha256 = [0; 32];
    sha256.copy_from_slice(sha.finish().as_ref());
    Ok(Sealed {
        sha256,
        length,
        sealed: sealed_len(length),
        crypto,
    })
}

/// A blob being opened, chunk by chunk, in order.
pub struct Opener {
    cipher: XChaCha20Poly1305,
    header: [u8; HEADER],
    length: u64,
    padded: u64,
    count: u64,
    next: u64,
    sha: ring::digest::Context,
    crypto: Duration,
}

impl fmt::Debug for Opener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opener")
            .field("length", &self.length)
            .field("next", &self.next)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl Opener {
    /// Opens the blob of a file of `length` bytes sealed under `key`, its
    /// first [`HEADER`] bytes `header`.
    ///
    /// # Errors
    ///
    /// The header is not a blob's, or of another chunk size.
    pub fn new(key: &BlobKey, length: u64, header: &[u8]) -> Result<Self, Error> {
        let header: [u8; HEADER] = header
            .try_into()
            .map_err(|_| Error::new("not a blob: its header is cut short"))?;
        if !header.starts_with(MAGIC) {
            return Err(Error::new("not a blob of this format (binbun-blob 1)"));
        }
        let chunk = header
            .get(MAGIC.len()..MAGIC.len() + 4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_be_bytes);
        if chunk != u32::try_from(CHUNK).ok() {
            return Err(Error::new(format!(
                "a blob of {chunk:?}-byte chunks; this binbun reads {CHUNK}"
            )));
        }
        let padded = padme(length);
        Ok(Self {
            cipher: key.cipher(),
            header,
            length,
            padded,
            count: chunks(padded),
            next: 0,
            sha: ring::digest::Context::new(&ring::digest::SHA256),
            crypto: Duration::ZERO,
        })
    }

    /// The bytes of the next chunk sealed (its tag included); `None` once
    /// every chunk is opened.
    pub fn next_len(&self) -> Option<usize> {
        (self.next < self.count).then(|| {
            let start = self.next * CHUNK_U64;
            usize::try_from((self.padded - start).min(CHUNK_U64)).unwrap_or(CHUNK) + TAG
        })
    }

    /// Opens the next chunk, `sealed` (of [`Self::next_len`] bytes), in
    /// place: the file's bytes in it (none of its padding).
    ///
    /// # Errors
    ///
    /// It does not open (tampered with, out of order, sealed under another
    /// key), or its padding is not zeros.
    pub fn open<'a>(&mut self, sealed: &'a mut Vec<u8>) -> Result<&'a [u8], Error> {
        let index = self.next;
        if Some(sealed.len()) != self.next_len() {
            return Err(Error::new(format!(
                "chunk {index} of the blob is {} bytes, not {:?}",
                sealed.len(),
                self.next_len()
            )));
        }
        let last = index + 1 == self.count;
        let counter = u32::try_from(index).map_err(|_| Error::new("a blob too large"))?;
        let prefix = self.header.get(MAGIC.len() + 4..).unwrap_or_default();
        let from = HEADER as u64 + index * (CHUNK_U64 + TAG as u64);
        let to = from + sealed.len() as u64;
        let began = Instant::now();
        self.cipher
            .decrypt_in_place(&nonce(prefix, counter, last), &self.header, sealed)
            .map_err(|_| {
                Error::new(format!(
                    "chunk {index} of the blob (bytes {from}..{to}) does not open: it was \
                     tampered with, or sealed under another key"
                ))
            })?;
        self.crypto += began.elapsed();
        self.next += 1;
        let start = index * CHUNK_U64;
        let real = usize::try_from(self.length.saturating_sub(start).min(CHUNK_U64))
            .unwrap_or(CHUNK)
            .min(sealed.len());
        let (file, padding) = sealed.split_at(real);
        if padding.iter().any(|byte| *byte != 0) {
            return Err(Error::new("the blob's padding is not zeros"));
        }
        self.sha.update(file);
        Ok(file)
    }

    /// The file's SHA-256, once every chunk is opened, and the time spent
    /// decrypting.
    ///
    /// # Errors
    ///
    /// Chunks are left: the blob was cut short.
    pub fn finish(self) -> Result<([u8; 32], Duration), Error> {
        if self.next < self.count {
            return Err(Error::new(format!(
                "the blob ends after chunk {} of {}: cut short",
                self.next, self.count
            )));
        }
        let mut sha256 = [0; 32];
        sha256.copy_from_slice(self.sha.finish().as_ref());
        Ok((sha256, self.crypto))
    }
}

/// Opens the whole blob read from `from` (of a file of `length` bytes
/// sealed under `key`), the file written to `to`: its SHA-256, and the
/// time spent decrypting.
///
/// # Errors
///
/// It is no blob, does not open (a chunk tampered with: which one is
/// said), is cut short or longer; `from` or `to` fails.
pub fn open(
    key: &BlobKey,
    length: u64,
    from: &mut impl Read,
    to: &mut impl Write,
) -> Result<([u8; 32], Duration), Error> {
    let mut header = [0; HEADER];
    if fill(from, &mut header)? < HEADER {
        return Err(Error::new("not a blob: its header is cut short"));
    }
    let mut opener = Opener::new(key, length, &header)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(CHUNK + TAG));
    while let Some(size) = opener.next_len() {
        buffer.clear();
        buffer.resize(size, 0);
        let got = fill(from, &mut buffer)?;
        buffer.truncate(got);
        let file = opener.open(&mut buffer)?;
        to.write_all(file)?;
    }
    let mut more = [0; 1];
    if fill(from, &mut more)? != 0 {
        return Err(Error::new("the blob goes on past its last chunk"));
    }
    opener.finish()
}

#[cfg(test)]
mod tests {
    use super::{BlobKey, CHUNK, HEADER, TAG, open, padme, seal, sealed_len};

    /// `length` bytes no two chunks of which are alike.
    fn file(length: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect()
    }

    fn sealed(key: &BlobKey, plain: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        let out = seal(key, None, plain.len() as u64, &mut &plain[..], &mut blob).unwrap();
        assert_eq!(out.sealed, blob.len() as u64);
        assert_eq!(out.sealed, sealed_len(plain.len() as u64));
        blob
    }

    #[test]
    fn padme_keeps_the_top_bits_and_costs_at_most_twelve_percent() {
        // The paper's examples, and the small lengths it leaves alone.
        assert_eq!(
            [0, 1, 2, 3, 7, 8, 9, 10].map(padme),
            [0, 1, 2, 3, 7, 8, 10, 10]
        );
        assert_eq!(padme(1000), 1024);
        assert_eq!(padme(940_000_000), 956_301_312);
        for length in (2..2_000_000u64).step_by(997).chain([u64::MAX >> 8]) {
            let padded = padme(length);
            assert!(padded >= length && padded <= length + length * 12 / 100 + 1);
            assert_eq!(padme(padded), padded, "{length}");
        }
    }

    #[test]
    fn an_offer_of_any_length_has_a_size_a_fetch_can_hold_it_to() {
        // The largest length that pads within a u64, and past it lengths
        // an offer may claim but no file has: the sizes saturate.
        let largest = u64::MAX - ((1 << 57) - 1);
        assert_eq!(padme(largest), largest);
        assert!(sealed_len(largest) > largest);
        for length in [largest + 1, u64::MAX] {
            assert_eq!(padme(length), u64::MAX);
            assert_eq!(sealed_len(length), u64::MAX);
        }
    }

    #[test]
    fn a_blob_opens_to_its_file_under_its_key_only() {
        let key = BlobKey::random().unwrap();
        for length in [0, 1, 100, CHUNK - 1, CHUNK, CHUNK + 1, 5 * CHUNK + 77] {
            let plain = file(length);
            let blob = sealed(&key, &plain);
            let mut out = Vec::new();
            let (sha, _) = open(&key, length as u64, &mut &blob[..], &mut out).unwrap();
            assert_eq!(out, plain);
            assert_eq!(
                sha,
                *ring::digest::digest(&ring::digest::SHA256, &plain).as_ref()
            );
            let other = BlobKey::random().unwrap();
            assert!(open(&other, length as u64, &mut &blob[..], &mut Vec::new()).is_err());
        }
        // Two files of one Padmé length make blobs of one size.
        assert_eq!(sealed_len(1001), sealed_len(1024));
        // The same key and prefix seal to the same bytes.
        let plain = file(3 * CHUNK);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        let prefix = Some([7; 19]);
        seal(&key, prefix, plain.len() as u64, &mut &plain[..], &mut a).unwrap();
        seal(&key, prefix, plain.len() as u64, &mut &plain[..], &mut b).unwrap();
        assert_eq!(a, b);
        assert!(
            !a.windows(64)
                .any(|window| plain.windows(64).next() == Some(window))
        );
    }

    #[test]
    fn a_chunk_tampered_with_cut_reordered_or_added_is_refused_by_name() {
        let key = BlobKey::random().unwrap();
        let length = 4 * CHUNK + 10;
        let plain = file(length);
        let blob = sealed(&key, &plain);
        let at = |index: usize| HEADER + index * (CHUNK + TAG);
        let refused = |blob: &[u8]| {
            open(&key, length as u64, &mut &blob[..], &mut Vec::new())
                .unwrap_err()
                .to_string()
        };
        let mut flipped = blob.clone();
        flipped[at(2) + 500] ^= 1;
        let why = refused(&flipped);
        assert!(
            why.starts_with("chunk 2 of the blob") && why.contains("tampered"),
            "{why}"
        );
        // The header is authenticated too: its prefix flipped, chunk 0 fails.
        let mut header = blob.clone();
        header[HEADER - 1] ^= 1;
        assert!(refused(&header).starts_with("chunk 0 "));
        // Cut after a whole chunk: the next is short, or missing.
        assert!(refused(&blob[..at(3)]).contains("chunk 3"));
        // Two chunks swapped: the first out of place fails.
        let mut swapped = blob.clone();
        let (one, two) = (blob[at(1)..at(2)].to_vec(), blob[at(2)..at(3)].to_vec());
        swapped[at(1)..at(2)].copy_from_slice(&two);
        swapped[at(2)..at(3)].copy_from_slice(&one);
        assert!(refused(&swapped).starts_with("chunk 1 "));
        // A blob that goes on, or of a file said to be shorter.
        let mut longer = blob.clone();
        longer.push(0);
        assert!(refused(&longer).contains("past its last chunk"));
        assert!(open(&key, 4 * CHUNK as u64, &mut &blob[..], &mut Vec::new()).is_err());
    }
}
