//! A shared project's keys and what they seal:
//!
//! - **Epoch keys** ([`EpochKey`]): 32 random bytes per epoch, made by the
//!   owner; a member's removal starts a new epoch. Each purpose has its
//!   own subkey, `HKDF-SHA256(E_n, salt = project, info = "binbun/v1/" +
//!   purpose)`.
//! - **Change envelopes** ([`seal`], [`open`], [`sealer`]): a change's
//!   signed head in the clear beside its body sealed with
//!   XChaCha20-Poly1305 under the epoch's `log` subkey and a random
//!   192-bit nonce, then signed by whoever sealed it (sync §2.2; the
//!   layout is [`binbun_sync::envelope`]'s):
//!
//!   ```text
//!   project:16 ‖ head ‖ author_sig:64 ‖ epoch:u32 ‖ nonce:24 ‖ ct ‖ sealer:32 ‖ seal_sig:64
//!   ct       = XChaCha20-Poly1305_{L_epoch}(body; aad = genesis ‖ change hash ‖ epoch)
//!   seal_sig = Ed25519_sealer("binbun/v1/seal" ‖ genesis ‖ change hash ‖ epoch ‖ BLAKE3(nonce ‖ ct))
//!   ```
//!
//!   (integers big-endian). `genesis` is the share's (the hash of its
//!   first membership record), never sent: two shares can have one
//!   routing id `project` (a home log shared twice), so that id is a
//!   locator only, in no signature and no associated data, and what is
//!   sealed in one share opens in no other. The head commits to the body,
//!   so the same change sealed twice has one identity; a sealing that
//!   does not open is that source's fault, no fork. The sealer is named
//!   only once its seal verifies.
//! - **Key wraps** ([`wrap`], [`unwrap`]): an epoch key sealed to one
//!   member's agreement key with HPKE (RFC 9180) in base mode,
//!   DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305;
//!   `info = "binbun/v1/keywrap" ‖ project ‖ epoch`, the member's identity
//!   key as associated data: `enc:32 ‖ ciphertext:48`.
//! - **History links** ([`seal_history`], [`open_history`]): the record
//!   starting epoch *n* ≥ 1 seals the subkeys of epoch *n* − 1 for
//!   changes, snapshots, offers and history ([`Subkeys`]) under epoch
//!   *n*'s `history` subkey, bound to the share's genesis, *n* and the record
//!   before: a member given a later epoch's key derives those of every
//!   earlier epoch, never an earlier epoch key.

use std::fmt;

use binbun_session::journal::{ChangeHash, ProjectId, PublicKey, SignedChange};
use binbun_sync::envelope::{Envelope, Parts};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::Error;

/// The bytes of the AEAD's tag.
const TAG: usize = 16;

/// What a change envelope's sealer signs first.
const SEAL: &[u8] = b"binbun/v1/seal";

/// `N` random bytes.
///
/// # Errors
///
/// The system has no randomness.
pub(crate) fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::new("the system has no randomness"))?;
    Ok(bytes)
}

/// One epoch's key: the root of what is sealed in it.
#[derive(Clone)]
pub struct EpochKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EpochKey(..)")
    }
}

impl EpochKey {
    /// A new one.
    ///
    /// # Errors
    ///
    /// The system has no randomness.
    pub fn random() -> Result<Self, Error> {
        Ok(Self(Zeroizing::new(random()?)))
    }

    /// Its subkey for `purpose` in `project`.
    fn subkey(&self, project: ProjectId, purpose: &str) -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0; 32]);
        let info = format!("binbun/v1/{purpose}");
        // 32 bytes is far below HKDF-SHA256's limit of 255 blocks.
        let _ = Hkdf::<Sha256>::new(Some(&project.0), self.0.as_slice())
            .expand(info.as_bytes(), key.as_mut_slice());
        key
    }

    /// Its subkey for changes in `project`, which seals envelopes
    /// ([`seal`]).
    pub fn log(&self, project: ProjectId) -> Zeroizing<[u8; 32]> {
        self.subkey(project, "log")
    }

    /// Its cipher for `purpose` (`presence`, `chat`) in `project`.
    pub(crate) fn cipher(&self, project: ProjectId, purpose: &str) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&Key::from(*self.subkey(project, purpose)))
    }

    /// Its subkeys in `project` that a member of a later epoch can derive
    /// ([`open_history`]).
    pub fn subkeys(&self, project: ProjectId) -> Subkeys {
        Subkeys {
            log: self.subkey(project, "log"),
            snapshot: self.subkey(project, "snapshot"),
            blobkey: self.subkey(project, "blobkey"),
            history: self.subkey(project, "history"),
        }
    }

    /// The key `bytes` (known-answer tests).
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// The bytes of a history link: `nonce:24 ‖ AEAD(L ‖ S ‖ B ‖ H) ‖ tag:16`.
pub const HISTORY: usize = 24 + 4 * 32 + TAG;

/// What a history link's associated data starts with.
const HISTORY_AAD: &[u8] = b"binbun/v1/history";

/// One epoch's subkeys that a member of a later epoch can derive from
/// the history links ([`open_history`]): for changes (`log`), snapshots
/// (`snapshot`), offers (`blobkey`) and the history link of the epoch
/// (`history`), each HKDF-SHA256 of the epoch key under the project as
/// salt and `binbun/v1/` and the purpose as info. Never the epoch key
/// itself: nothing else of the epoch (presence, chat, the binary sealed)
/// opens with them.
#[derive(Clone, PartialEq, Eq)]
pub struct Subkeys {
    log: Zeroizing<[u8; 32]>,
    snapshot: Zeroizing<[u8; 32]>,
    blobkey: Zeroizing<[u8; 32]>,
    history: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for Subkeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Subkeys(..)")
    }
}

impl Subkeys {
    /// The key changes are sealed under.
    pub fn log(&self) -> &[u8; 32] {
        &self.log
    }

    /// The key snapshots are sealed under.
    pub fn snapshot(&self) -> &[u8; 32] {
        &self.snapshot
    }

    /// The key offers are sealed under.
    pub fn blobkey(&self) -> &[u8; 32] {
        &self.blobkey
    }

    /// The key the history link of the epoch is sealed under.
    pub fn history(&self) -> &[u8; 32] {
        &self.history
    }

    /// `L ‖ S ‖ B ‖ H`, as a history link seals them.
    fn to_bytes(&self) -> Zeroizing<[u8; 128]> {
        let mut bytes = Zeroizing::new([0; 128]);
        let keys = [&self.log, &self.snapshot, &self.blobkey, &self.history];
        for (part, key) in bytes.as_chunks_mut::<32>().0.iter_mut().zip(keys) {
            *part = **key;
        }
        bytes
    }

    /// The keys `bytes` (`L ‖ S ‖ B ‖ H`) hold, if 128 bytes.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 128 {
            return None;
        }
        let key = |at: usize| -> Option<Zeroizing<[u8; 32]>> {
            Some(Zeroizing::new(
                bytes.get(at * 32..(at + 1) * 32)?.try_into().ok()?,
            ))
        };
        Some(Self {
            log: key(0)?,
            snapshot: key(1)?,
            blobkey: key(2)?,
            history: key(3)?,
        })
    }
}

/// What a history link authenticates beside what it seals:
/// `"binbun/v1/history" ‖ genesis ‖ epoch:u32 ‖ prev`.
fn history_aad(genesis: &[u8; 32], epoch: u32, prev: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HISTORY_AAD.len() + 32 + 4 + 32);
    aad.extend_from_slice(HISTORY_AAD);
    aad.extend_from_slice(genesis);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(prev);
    aad
}

/// The history link of the record that starts epoch `epoch` (≥ 1) of
/// the share whose genesis is `genesis`, whose predecessor's hash is
/// `prev`: the subkeys of the epoch before (`earlier`) sealed under the
/// `history` subkey of the new one (`later`), under a random nonce:
///
/// ```text
/// nonce:24 ‖ XChaCha20-Poly1305_{H_n}(L_{n−1} ‖ S_{n−1} ‖ B_{n−1} ‖ H_{n−1};
///                                     aad = "binbun/v1/history" ‖ genesis ‖ n:u32 ‖ prev)
/// ```
///
/// # Errors
///
/// No randomness for the nonce.
pub fn seal_history(
    later: &Subkeys,
    genesis: &[u8; 32],
    epoch: u32,
    prev: &[u8; 32],
    earlier: &Subkeys,
) -> Result<[u8; HISTORY], Error> {
    seal_history_with(later, genesis, epoch, prev, earlier, random()?)
}

/// [`seal_history`] under `nonce`.
fn seal_history_with(
    later: &Subkeys,
    genesis: &[u8; 32],
    epoch: u32,
    prev: &[u8; 32],
    earlier: &Subkeys,
    nonce: [u8; 24],
) -> Result<[u8; HISTORY], Error> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*later.history));
    let plain = earlier.to_bytes();
    let sealed = cipher
        .encrypt(
            &XNonce::from(nonce),
            chacha20poly1305::aead::Payload {
                msg: plain.as_slice(),
                aad: &history_aad(genesis, epoch, prev),
            },
        )
        .map_err(|_| Error::new("a history link that does not seal"))?;
    let mut link = [0; HISTORY];
    link[..24].copy_from_slice(&nonce);
    link.get_mut(24..)
        .filter(|rest| rest.len() == sealed.len())
        .ok_or_else(|| Error::new("a history link of another length"))?
        .copy_from_slice(&sealed);
    Ok(link)
}

/// The subkeys of epoch `epoch − 1` that `link`, the history link of the
/// record starting epoch `epoch` of the share whose genesis is `genesis`
/// and whose predecessor's hash is `prev`, seals under `later` (epoch
/// `epoch`'s subkeys); `None` if it does not open (another key, epoch,
/// share or branch, or altered).
pub fn open_history(
    later: &Subkeys,
    genesis: &[u8; 32],
    epoch: u32,
    prev: &[u8; 32],
    link: &[u8; HISTORY],
) -> Option<Subkeys> {
    let (nonce, sealed) = link.split_first_chunk::<24>()?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*later.history));
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(*nonce),
                chacha20poly1305::aead::Payload {
                    msg: sealed,
                    aad: &history_aad(genesis, epoch, prev),
                },
            )
            .ok()?,
    );
    Subkeys::from_bytes(&plain)
}

/// What an envelope's body is sealed with besides its key: the share's
/// genesis, the change's hash and the epoch (`genesis ‖ change hash ‖
/// epoch`).
fn envelope_aad(genesis: &[u8; 32], change: ChangeHash, epoch: u32) -> [u8; 68] {
    let mut aad = [0; 68];
    aad[..32].copy_from_slice(genesis);
    aad[32..64].copy_from_slice(&change.0);
    aad[64..].copy_from_slice(&epoch.to_be_bytes());
    aad
}

/// What the sealer of an envelope signs: [`SEAL`], the share's genesis,
/// the change's hash, the epoch and the BLAKE3 of the nonce and the
/// ciphertext.
fn seal_message(
    genesis: &[u8; 32],
    change: ChangeHash,
    epoch: u32,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut sealed = blake3::Hasher::new();
    sealed.update(nonce);
    sealed.update(ciphertext);
    let mut message = Vec::with_capacity(SEAL.len() + 68 + 32);
    message.extend_from_slice(SEAL);
    message.extend_from_slice(&envelope_aad(genesis, change, epoch));
    message.extend_from_slice(sealed.finalize().as_bytes());
    message
}

/// `signed` sealed for the share whose genesis is `genesis` in epoch
/// `epoch` under that epoch's `log` subkey `log`, by `sealer`: its
/// envelope (sync §2.2), routed to `project` (a locator only, bound by
/// nothing).
///
/// # Errors
///
/// No randomness for the nonce; a body too long to seal.
pub fn seal(
    log: &[u8; 32],
    project: ProjectId,
    genesis: &[u8; 32],
    epoch: u32,
    signed: &SignedChange,
    sealer: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let change = signed.hash();
    let nonce: [u8; 24] = random()?;
    let ciphertext = XChaCha20Poly1305::new(&Key::from(*log))
        .encrypt(
            &XNonce::from(nonce),
            chacha20poly1305::aead::Payload {
                msg: &signed.body,
                aad: &envelope_aad(genesis, change, epoch),
            },
        )
        .map_err(|_| Error::new("too long to seal"))?;
    let seal_sig = sealer
        .sign(&seal_message(genesis, change, epoch, &nonce, &ciphertext))
        .to_bytes();
    Envelope::write(&Parts {
        project,
        signed_head: &signed.head.bytes(),
        epoch,
        nonce: &nonce,
        ciphertext: &ciphertext,
        sealer: &sealer.verifying_key().to_bytes(),
        seal_sig: &seal_sig,
    })
    .ok_or_else(|| Error::new("a change that makes no envelope"))
}

/// The body sealed in `envelope`, whose head's hash is `change`, under
/// its epoch's `log` subkey `log`, in the share whose genesis is
/// `genesis`; `None` if it does not open (another key, share, change or
/// epoch, or tampered with).
pub fn open(
    log: &[u8; 32],
    genesis: &[u8; 32],
    envelope: &Envelope<'_>,
    change: ChangeHash,
) -> Option<Vec<u8>> {
    XChaCha20Poly1305::new(&Key::from(*log))
        .decrypt(
            &XNonce::from(envelope.nonce()),
            chacha20poly1305::aead::Payload {
                msg: envelope.ciphertext(),
                aad: &envelope_aad(genesis, change, envelope.epoch()),
            },
        )
        .ok()
}

/// Who sealed `envelope`, whose head's hash is `change`, if its seal
/// verifies in the share whose genesis is `genesis`: only then may a
/// notice name the sealer.
pub fn sealer(
    envelope: &Envelope<'_>,
    genesis: &[u8; 32],
    change: ChangeHash,
) -> Option<PublicKey> {
    let key = envelope.sealer();
    let message = seal_message(
        genesis,
        change,
        envelope.epoch(),
        &envelope.nonce(),
        envelope.ciphertext(),
    );
    VerifyingKey::from_bytes(&key)
        .ok()?
        .verify_strict(&message, &Signature::from_bytes(&envelope.seal_sig()))
        .ok()?;
    Some(PublicKey(key))
}

/// `plaintext` sealed with `cipher` under a random nonce: `nonce:24 ‖
/// ciphertext ‖ tag:16`, with no header (presence, chat).
///
/// # Errors
///
/// No randomness for the nonce.
pub(crate) fn seal_bare(cipher: &XChaCha20Poly1305, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    seal_bound(cipher, plaintext, &[])
}

/// [`seal_bare`] with `aad` as associated data: what it is for and where.
///
/// # Errors
///
/// No randomness for the nonce.
pub(crate) fn seal_bound(
    cipher: &XChaCha20Poly1305,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let nonce: [u8; 24] = random()?;
    let sealed = cipher
        .encrypt(
            &XNonce::from(nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::new("too long to seal"))?;
    let mut out = Vec::with_capacity(24 + sealed.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// What [`seal_bare`] sealed in `sealed` with `cipher`; `None` if it does
/// not open (another key, tampered with).
pub(crate) fn open_bare(cipher: &XChaCha20Poly1305, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    open_bound(cipher, sealed, &[])
}

/// What [`seal_bound`] sealed in `sealed` with `cipher` and `aad`; `None`
/// if it does not open (another key or associated data, tampered with).
pub(crate) fn open_bound(
    cipher: &XChaCha20Poly1305,
    sealed: &[u8],
    aad: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let (nonce, rest) = sealed.split_first_chunk::<24>()?;
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            chacha20poly1305::aead::Payload { msg: rest, aad },
        )
        .ok()
        .map(Zeroizing::new)
}

/// What a key wrap's HPKE context names: the project and the epoch.
fn wrap_info(project: ProjectId, epoch: u32) -> Vec<u8> {
    let mut info = b"binbun/v1/keywrap".to_vec();
    info.extend_from_slice(&project.0);
    info.extend_from_slice(&epoch.to_be_bytes());
    info
}

/// The cipher of what this install alone keeps for `project` beside it
/// (`purpose`: the blobs it offers, and their keys): a subkey of its
/// identity's secret, `HKDF-SHA256(secret, salt = project, info =
/// "binbun/v1/local/" + purpose)`.
pub(crate) fn local(secret: &[u8; 32], project: ProjectId, purpose: &str) -> XChaCha20Poly1305 {
    let mut key = Zeroizing::new([0; 32]);
    let info = format!("binbun/v1/local/{purpose}");
    // 32 bytes is far below HKDF-SHA256's limit of 255 blocks.
    let _ =
        Hkdf::<Sha256>::new(Some(&project.0), secret).expand(info.as_bytes(), key.as_mut_slice());
    XChaCha20Poly1305::new(&Key::from(*key))
}

/// `key` (epoch `epoch` of `project`) wrapped to `member`, whose
/// agreement key is `agreement`.
///
/// # Errors
///
/// `agreement` is no X25519 key, or the system has no randomness.
pub fn wrap(
    key: &EpochKey,
    project: ProjectId,
    epoch: u32,
    member: PublicKey,
    agreement: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let recipient = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(agreement)
        .map_err(|_| Error::new("not an agreement key"))?;
    let (enc, sealed) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &recipient,
        &wrap_info(project, epoch),
        key.0.as_slice(),
        &member.0,
    )
    .map_err(|error| Error::new(format!("cannot wrap a key: {error}")))?;
    let mut wrapped = enc.to_bytes().to_vec();
    wrapped.extend_from_slice(&sealed);
    Ok(wrapped)
}

/// The epoch key `wrapped` holds for `member` (epoch `epoch` of
/// `project`), opened with `member`'s agreement secret.
///
/// # Errors
///
/// It is no wrap, or not one to this member for this epoch.
pub fn unwrap(
    wrapped: &[u8],
    project: ProjectId,
    epoch: u32,
    member: PublicKey,
    secret: &[u8; 32],
) -> Result<EpochKey, Error> {
    let fail = || Error::new(format!("cannot open epoch {epoch}'s key"));
    let (enc, sealed) = wrapped.split_at_checked(32).ok_or_else(fail)?;
    let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(enc).map_err(|_| fail())?;
    let secret = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(secret).map_err(|_| fail())?;
    let opened = Zeroizing::new(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &secret,
            &enc,
            &wrap_info(project, epoch),
            sealed,
            &member.0,
        )
        .map_err(|_| fail())?,
    );
    let key = <[u8; 32]>::try_from(opened.as_slice()).map_err(|_| fail())?;
    Ok(EpochKey(Zeroizing::new(key)))
}

#[cfg(test)]
mod tests {
    use binbun_session::identity::Identity;
    use binbun_session::journal::{
        Body, ChainId, ChangeHash, Head, ProjectId, SignedChange, SignedHead, Signer,
    };
    use binbun_sync::envelope::Envelope;
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
    use data_encoding::HEXLOWER;
    use ed25519_dalek::SigningKey;
    use hkdf::Hkdf;
    use sha2::Sha256;

    use super::{
        EpochKey, HISTORY, open, open_history, seal, seal_history_with, sealer, unwrap, wrap,
    };

    const PROJECT: ProjectId = ProjectId([3; 16]);

    /// The share's genesis in the vectors and tests.
    const GENESIS: [u8; 32] = [0x47; 32];

    /// Another share's, of the same routing id `PROJECT` (a home log
    /// shared twice).
    const OTHER: [u8; 32] = [0x48; 32];

    /// Epoch `n`'s key in the vectors: 32 bytes of `0x10 + n`.
    fn vector_key(n: u8) -> EpochKey {
        EpochKey::from_bytes([0x10 + n; 32])
    }

    /// The hash of the record before the one starting epoch `n`: 32
    /// bytes of `0xa0 + n`.
    fn vector_prev(n: u8) -> [u8; 32] {
        [0xa0 + n; 32]
    }

    /// The nonce of epoch `n`'s link: 24 bytes of `0x20 + n`.
    fn vector_nonce(n: u8) -> [u8; 24] {
        [0x20 + n; 24]
    }

    /// The history link of epoch `n` of the vectors, made here from the
    /// primitives as sync §6.3 lays it out, apart from the code tested.
    fn by_hand(n: u8) -> Vec<u8> {
        let subkey = |epoch: u8, purpose: &str| {
            let mut key = [0; 32];
            Hkdf::<Sha256>::new(Some(&PROJECT.0), &[0x10 + epoch; 32])
                .expand(format!("binbun/v1/{purpose}").as_bytes(), &mut key)
                .unwrap();
            key
        };
        let plain: Vec<u8> = ["log", "snapshot", "blobkey", "history"]
            .into_iter()
            .flat_map(|purpose| subkey(n - 1, purpose))
            .collect();
        let mut aad = b"binbun/v1/history".to_vec();
        aad.extend(GENESIS);
        aad.extend(u32::from(n).to_be_bytes());
        aad.extend(vector_prev(n));
        let cipher = XChaCha20Poly1305::new(&Key::from(subkey(n, "history")));
        let mut link = vector_nonce(n).to_vec();
        link.extend(
            cipher
                .encrypt(
                    &XNonce::from(vector_nonce(n)),
                    Payload {
                        msg: &plain,
                        aad: &aad,
                    },
                )
                .unwrap(),
        );
        link
    }

    /// The history links of epochs 1, 2 and 3 of the vectors.
    const VECTORS: [&str; 3] = [
        "2121212121212121212121212121212121212121212121210597afcdccc710935653cd5956ee7c4f0cdd1e6394ed1cf4a16ab7c9db0839fdced70943e6bb1fea2c3b74f709dad6c5a7a65f216e6bf6afa48cf9900fb7d5bab74b3c98d0a3ed79bbba9b6b4df01dcce8fd4bf73e91cf46881afe0b8bb852bb14058ea280fcc787adedab724b3437db6d858da965faf3b68e27b8ff74150ab9fc27f39630f9b2273c2bd76aeb985c68",
        "222222222222222222222222222222222222222222222222be836e2c4b9e4c801c7b288fa2902477bc822525549368e22cd6b2ffcf584d6599311b6edb6b89eed306fa0931ab240156db8ffd706cd7a7ef504291b037f60bbb634c2cbdc81fe85ec6475a6c1b2d58cb1298d4f22b54b69942aed8177baf522c91473c072c6a50a5488997fb2c79be1e4e861a26ab3eba4f697c5fdd34687cab6aecc0dd7c07321e7164d76fbfee4f",
        "2323232323232323232323232323232323232323232323234b48fbf0bbb402380d4a036296b19de1ec7c3f49a1cec7564b0b92b7425b3152e9965633308ba30f04020d3e99c81b0e5c5a21e620fd44281831525ffdd642b57c4b8e9d0b3b43365f6541e6c7b6795b21cbd317a2ef7af31df11a0017a8e321d0cde123f75d77ca10ef91af6608e2f8dc9be0211f254b740450ea3b95756fdec62706dcc22a875c31cd8dbd4d6127ab",
    ];

    #[test]
    fn history_links_match_their_known_answers_and_open_down_to_epoch_0() {
        let mut later = vector_key(3).subkeys(PROJECT);
        for n in (1..=3u8).rev() {
            let link = seal_history_with(
                &vector_key(n).subkeys(PROJECT),
                &GENESIS,
                n.into(),
                &vector_prev(n),
                &vector_key(n - 1).subkeys(PROJECT),
                vector_nonce(n),
            )
            .unwrap();
            assert_eq!(link.len(), HISTORY);
            assert_eq!(link.to_vec(), by_hand(n));
            assert_eq!(
                HEXLOWER.encode(&link),
                VECTORS[usize::from(n - 1)],
                "epoch {n}"
            );
            // Walked down from epoch 3's key alone.
            let earlier = open_history(&later, &GENESIS, n.into(), &vector_prev(n), &link).unwrap();
            assert_eq!(earlier, vector_key(n - 1).subkeys(PROJECT));
            later = earlier;
        }
    }

    #[test]
    fn a_history_link_altered_or_moved_does_not_open_and_wrong_keys_show() {
        let (later, earlier) = (
            vector_key(2).subkeys(PROJECT),
            vector_key(1).subkeys(PROJECT),
        );
        let (nonce, prev) = (vector_nonce(2), vector_prev(2));
        let link = seal_history_with(&later, &GENESIS, 2, &prev, &earlier, nonce).unwrap();
        assert_eq!(
            open_history(&later, &GENESIS, 2, &prev, &link),
            Some(earlier.clone())
        );
        // A byte altered: of the nonce, of each key wrapped, of the tag.
        for at in [0, 23, 24, 24 + 32, 24 + 64, 24 + 96, HISTORY - 1] {
            let mut altered = link;
            altered[at] ^= 1;
            assert!(
                open_history(&later, &GENESIS, 2, &prev, &altered).is_none(),
                "{at}"
            );
        }
        // Its associated data: another share (of the same routing id),
        // epoch, or branch (another record before).
        assert!(open_history(&later, &OTHER, 2, &prev, &link).is_none());
        assert!(open_history(&later, &GENESIS, 3, &prev, &link).is_none());
        assert!(open_history(&later, &GENESIS, 2, &vector_prev(1), &link).is_none());
        // Under another epoch's subkeys.
        let other = vector_key(3).subkeys(PROJECT);
        assert!(open_history(&other, &GENESIS, 2, &prev, &link).is_none());
        // Each key wrapped replaced in turn: the link opens, and gives
        // what it wrapped, not the epoch's keys (what a member holding
        // them checks).
        for which in 0..4 {
            let mut wrong = earlier.clone();
            let key = match which {
                0 => &mut wrong.log,
                1 => &mut wrong.snapshot,
                2 => &mut wrong.blobkey,
                _ => &mut wrong.history,
            };
            key[0] ^= 1;
            let link = seal_history_with(&later, &GENESIS, 2, &prev, &wrong, nonce).unwrap();
            let opened = open_history(&later, &GENESIS, 2, &prev, &link).unwrap();
            assert_eq!(opened, wrong);
            assert_ne!(opened, earlier);
        }
    }

    /// A change (number 7 of a chain), its body some text.
    fn signed() -> SignedChange {
        let body = b"a change named aes_init".to_vec();
        let head = Head {
            chain: ChainId([9; 16]),
            seq: 7,
            prev: ChangeHash([1; 32]),
            body: Body::commitment(&body),
            origin: None,
        };
        SignedChange {
            head: SignedHead::sign(head, &Signer::from_seed(&[5; 32])),
            body,
        }
    }

    /// Whoever seals: an identity of its own.
    fn sealing() -> SigningKey {
        SigningKey::from_bytes(&Identity::ephemeral().unwrap().secret())
    }

    #[test]
    fn an_envelope_opens_under_its_key_only_and_any_flipped_byte_fails() {
        let key = EpochKey::random().unwrap();
        let change = signed();
        let hash = change.hash();
        let by = sealing();
        let bytes = seal(&key.log(PROJECT), PROJECT, &GENESIS, 2, &change, &by).unwrap();
        let envelope = Envelope::parse(&bytes).unwrap();
        assert_eq!(envelope.signed_head(), &*change.head.bytes());
        assert_eq!((envelope.project(), envelope.epoch()), (PROJECT, 2));
        assert_eq!(
            open(&key.log(PROJECT), &GENESIS, &envelope, hash).unwrap(),
            change.body
        );
        let by_key = binbun_session::journal::PublicKey(by.verifying_key().to_bytes());
        assert_eq!(sealer(&envelope, &GENESIS, hash), Some(by_key));
        // Nothing of the change is readable on the wire.
        let text = b"aes_init";
        assert!(!bytes.windows(text.len()).any(|window| window == text));
        // Another epoch's key, the same in another project, or the body
        // put under another change's head, opens nothing.
        let other = EpochKey::random().unwrap();
        assert!(open(&other.log(PROJECT), &GENESIS, &envelope, hash).is_none());
        assert!(open(&key.log(ProjectId([4; 16])), &GENESIS, &envelope, hash).is_none());
        assert!(open(&key.log(PROJECT), &GENESIS, &envelope, ChangeHash([0; 32])).is_none());
        // The routing id is a locator: altered, the envelope still opens
        // and names its sealer in its share.
        for at in 0..16 {
            let mut moved = bytes.clone();
            moved[at] ^= 1;
            let moved = Envelope::parse(&moved).unwrap();
            assert_eq!(
                open(&key.log(PROJECT), &GENESIS, &moved, hash).as_ref(),
                Some(&change.body)
            );
            assert_eq!(sealer(&moved, &GENESIS, hash), Some(by_key));
        }
        // The epoch, nonce and ciphertext are covered by the tag and the
        // seal; the sealer and its signature by the seal.
        let head = 16 + envelope.signed_head().len();
        for at in head..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[at] ^= 1;
            let tampered = Envelope::parse(&tampered).unwrap();
            assert!(
                sealer(&tampered, &GENESIS, hash).is_none(),
                "byte {at} flipped sealed"
            );
            if at < bytes.len() - 96 {
                let opened = open(&key.log(PROJECT), &GENESIS, &tampered, hash);
                assert!(opened.is_none(), "byte {at} flipped opened");
            }
        }
        // Two seals of one change differ (random nonces).
        assert_ne!(
            seal(&key.log(PROJECT), PROJECT, &GENESIS, 2, &change, &by).unwrap(),
            bytes
        );
    }

    #[test]
    fn a_seal_of_one_share_neither_opens_nor_names_its_sealer_in_another_of_its_routing_id() {
        // A home log shared twice: one routing id, one log key here, two
        // geneses.
        let key = EpochKey::random().unwrap();
        let change = signed();
        let hash = change.hash();
        let by = sealing();
        let bytes = seal(&key.log(PROJECT), PROJECT, &GENESIS, 3, &change, &by).unwrap();
        let envelope = Envelope::parse(&bytes).unwrap();
        let by_key = binbun_session::journal::PublicKey(by.verifying_key().to_bytes());
        assert_eq!(
            open(&key.log(PROJECT), &GENESIS, &envelope, hash),
            Some(change.body)
        );
        assert_eq!(sealer(&envelope, &GENESIS, hash), Some(by_key));
        assert!(open(&key.log(PROJECT), &OTHER, &envelope, hash).is_none());
        assert!(sealer(&envelope, &OTHER, hash).is_none());
    }

    #[test]
    fn a_wrap_opens_for_its_member_epoch_and_project_only() {
        let (ann, bob) = (
            Identity::ephemeral().unwrap(),
            Identity::ephemeral().unwrap(),
        );
        let key = EpochKey::random().unwrap();
        let wrapped = wrap(&key, PROJECT, 4, ann.public(), &ann.agreement()).unwrap();
        let opened = unwrap(&wrapped, PROJECT, 4, ann.public(), &ann.agreement_secret()).unwrap();
        let change = signed();
        let bytes = seal(&key.log(PROJECT), PROJECT, &GENESIS, 4, &change, &sealing()).unwrap();
        let envelope = Envelope::parse(&bytes).unwrap();
        assert_eq!(
            open(&opened.log(PROJECT), &GENESIS, &envelope, change.hash()),
            Some(change.body)
        );
        assert!(unwrap(&wrapped, PROJECT, 4, bob.public(), &bob.agreement_secret()).is_err());
        assert!(unwrap(&wrapped, PROJECT, 5, ann.public(), &ann.agreement_secret()).is_err());
        assert!(
            unwrap(
                &wrapped,
                ProjectId([4; 16]),
                4,
                ann.public(),
                &ann.agreement_secret()
            )
            .is_err()
        );
        assert!(unwrap(&wrapped, PROJECT, 4, bob.public(), &ann.agreement_secret()).is_err());
    }
}
