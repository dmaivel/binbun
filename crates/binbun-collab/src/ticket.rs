//! What people pass each other by hand: **tickets** to join a shared
//! project (from its host) and **identity cards**. Both are text: a kind
//! (`binbun`, `binbunid`) then the postcard of the value in
//! lower-case base32 without padding, the shape of iroh's tickets, read in
//! either case (a QR code carries it in upper case, which its
//! alphanumeric mode packs tighter). None holds a secret.
//!
//! A ticket to a project on one slice of a universal Mach-O file names
//! that slice's architecture ([`JoinTicket::arch`]), so a joiner opens the
//! same slice whatever its machine; a ticket to any other binary names
//! none.

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use binbun_bounded::{self as bounded, Bounded, Bounds, Text};
use binbun_session::identity::Identity;
use binbun_session::journal::{ProjectId, PublicKey};
use data_encoding::{BASE32_NOPAD, HEXLOWER};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::wire;

/// The most bytes of a relay's URL in an address.
pub const MAX_RELAY: usize = 512;

/// The most direct addresses in an address: past them, the first are
/// kept.
pub const MAX_DIRECT: usize = 32;

/// The most bytes of a universal binary's slice's architecture (`x86_64`,
/// `arm64e`), as a ticket, an offer or a membership record names it.
pub const MAX_ARCH: usize = 64;

/// Where a peer is reached: its identity key, and a relay and direct
/// addresses if known.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerAddr {
    /// Its identity key (its endpoint's id).
    pub id: PublicKey,
    /// Its home relay's URL.
    pub relay: Option<Text<MAX_RELAY>>,
    /// Its direct addresses.
    pub direct: Bounded<SocketAddr, MAX_DIRECT>,
}

impl Bounds for PeerAddr {}

/// The ticket's flag: the host wants peers on its LAN only (no relay).
pub const LAN_ONLY: u8 = 1;

/// A ticket to ask to join a shared project. It holds no secret: the
/// host approves who joins, and forgets the invite when its share
/// closes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinTicket {
    /// The format: 1.
    pub v: u8,
    /// The host.
    pub host: PeerAddr,
    /// The project's owner, whose membership chain the joiner checks.
    pub owner: PublicKey,
    /// The shared project.
    pub project: ProjectId,
    /// Random per share: a dialer without it is refused before anyone is
    /// asked.
    pub invite: [u8; 16],
    /// [`LAN_ONLY`].
    pub flags: u8,
    /// The architecture of the universal file's slice shared (`x86_64`,
    /// `arm64e`), if the binary is one.
    pub arch: Option<Text<MAX_ARCH>>,
}

impl JoinTicket {
    /// Whether the host wants peers on its LAN only ([`LAN_ONLY`]).
    pub fn lan_only(&self) -> bool {
        self.flags & LAN_ONLY != 0
    }
}

impl Bounds for JoinTicket {}

// The invite is what lets a dialler ask to join: never in debug output.
impl fmt::Debug for JoinTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinTicket")
            .field("v", &self.v)
            .field("host", &self.host)
            .field("owner", &self.owner)
            .field("project", &self.project)
            .field("invite", &"…")
            .field("flags", &self.flags)
            .field("arch", &self.arch)
            .finish()
    }
}

/// Writes `value` as `kind` then base32: encoded within [`MAX_BYTES`]
/// (I2), never more than a text can carry.
fn encode<T: Serialize>(kind: &str, value: &T, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let bytes = bounded::encode(value, MAX_BYTES).map_err(|_| fmt::Error)?;
    write!(
        f,
        "{kind}{}",
        BASE32_NOPAD.encode(&bytes).to_ascii_lowercase()
    )
}

/// The value written as `kind` then base32 in `text` (either case).
fn decode<T: Bounds>(kind: &str, text: &str) -> Result<T, Error> {
    let bytes = decode_bytes(kind, text)?;
    bounded::decode(&bytes).map_err(|_| not_a(kind))
}

/// That a text is not of `kind`.
fn not_a(kind: &str) -> Error {
    Error::new(format!("not a {kind} text"))
}

/// The most characters of a ticket's or a card's base32, past its kind:
/// a ticket's postcard is under 2 KiB (an address of [`MAX_DIRECT`]
/// direct addresses and a relay of [`MAX_RELAY`] bytes, an architecture
/// of [`MAX_ARCH`]), 3,277 characters, a card's far less.
pub const MAX_TEXT: usize = 4096;

/// The most bytes a text of [`MAX_TEXT`] base32 characters carries.
const MAX_BYTES: usize = MAX_TEXT * 5 / 8;

/// The bytes written as `kind` then base32 in `text` (either case): a
/// text longer than [`MAX_TEXT`] refused before it is copied or decoded.
fn decode_bytes(kind: &str, text: &str) -> Result<Vec<u8>, Error> {
    let text = text.trim();
    let body = text
        .get(..kind.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(kind))
        .and_then(|_| text.get(kind.len()..))
        .ok_or_else(|| not_a(kind))?;
    if body.len() > MAX_TEXT {
        return Err(Error::new(format!(
            "not a {kind} text: longer than {MAX_TEXT} characters"
        )));
    }
    BASE32_NOPAD
        .decode(body.to_ascii_uppercase().as_bytes())
        .map_err(|_| not_a(kind))
}

impl fmt::Display for JoinTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        encode("binbun", self, f)
    }
}

impl FromStr for JoinTicket {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        if starts(text, "binbunid") {
            return Err(Error::new("an identity card, not a ticket"));
        }
        let ticket: Self = decode("binbun", text)?;
        format_one(ticket.v)?;
        Ok(ticket)
    }
}

/// Whether `text` starts with `kind` (in either case).
fn starts(text: &str, kind: &str) -> bool {
    text.trim()
        .get(..kind.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(kind))
}

/// Refuses a text of a format other than 1.
fn format_one(v: u8) -> Result<(), Error> {
    if v == 1 {
        Ok(())
    } else {
        Err(Error::new(format!(
            "a text of format {v}; this binbun reads format 1"
        )))
    }
}

/// A participant's identity card: their identity and agreement
/// keys and name, signed by the identity key. Names and avatars beyond a
/// name come with the GUI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Card {
    /// Their identity key.
    pub key: PublicKey,
    /// Their agreement key, which receives the project's keys.
    pub agreement: [u8; 32],
    /// Their name.
    pub name: Text<NAME_BYTES>,
    /// The identity key's signature of the rest.
    #[serde(with = "wire::signature")]
    pub sig: Signature,
}

impl Bounds for Card {}

/// The most characters of a name.
const NAME: usize = 64;

/// The most bytes of a name: [`NAME`] characters of four bytes.
pub const NAME_BYTES: usize = 4 * NAME;

/// Whether `text` is at most `most` characters, none of them a control
/// character, a format character (Unicode's `Cf`: bidirectional
/// overrides, zero-width ones, tags) or a line or paragraph separator,
/// any of which moves or hides what is shown around it.
pub fn plain(text: &str, most: usize) -> bool {
    text.chars().take(most.saturating_add(1)).count() <= most && !text.chars().any(unshown)
}

/// `text`'s first `most` characters but those [`plain`] refuses.
pub fn plain_text(text: &str, most: usize) -> String {
    text.chars().filter(|c| !unshown(*c)).take(most).collect()
}

/// Whether `c` is a control character, a format character (Unicode 16's
/// `Cf`) or a line or paragraph separator.
fn unshown(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{ad}'
                | '\u{600}'..='\u{605}'
                | '\u{61c}'
                | '\u{6dd}'
                | '\u{70f}'
                | '\u{890}'..='\u{891}'
                | '\u{8e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
}

impl Card {
    /// `identity`'s card naming them `name`: its first 64 characters but
    /// those [`plain`] refuses.
    pub fn new(identity: &Identity, name: &str) -> Self {
        let name = Text::truncated(&plain_text(name, NAME));
        let signer = SigningKey::from_bytes(&identity.secret());
        let sig = signer.sign(&Self::signed(
            identity.public(),
            &identity.agreement(),
            &name,
        ));
        Self {
            key: identity.public(),
            agreement: identity.agreement(),
            name,
            sig,
        }
    }

    /// The bytes a card's signature covers.
    fn signed(key: PublicKey, agreement: &[u8; 32], name: &str) -> Vec<u8> {
        let mut bytes = b"binbun/v1/card".to_vec();
        bytes.extend_from_slice(&key.0);
        bytes.extend_from_slice(agreement);
        bytes.extend_from_slice(name.as_bytes());
        bytes
    }

    /// Whether its key signed it, and its name is plain text ([`plain`])
    /// of at most 64 characters.
    pub fn verifies(&self) -> bool {
        plain(&self.name, NAME)
            && VerifyingKey::from_bytes(&self.key.0).is_ok_and(|key| {
                key.verify_strict(
                    &Self::signed(self.key, &self.agreement, &self.name),
                    &self.sig,
                )
                .is_ok()
            })
    }
}

impl fmt::Display for Card {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        encode("binbunid", self, f)
    }
}

impl FromStr for Card {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        let card: Self = decode("binbunid", text)?;
        if !card.verifies() {
            return Err(Error::new("an identity card its key did not sign"));
        }
        Ok(card)
    }
}

/// `key`'s fingerprint, to compare by voice: 20 hexadecimal digits
/// of its BLAKE3, in groups of 4.
pub fn fingerprint(key: PublicKey) -> String {
    let hash = blake3::hash(&key.0);
    let hex = HEXLOWER.encode(hash.as_bytes().first_chunk::<10>().unwrap_or(&[0; 10]));
    hex.as_bytes()
        .chunks(4)
        .map(|group| String::from_utf8_lossy(group).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use binbun_bounded::{Bounded, Text};
    use binbun_session::identity::Identity;
    use binbun_session::journal::ProjectId;
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::{
        Card, JoinTicket, LAN_ONLY, MAX_ARCH, MAX_BYTES, MAX_DIRECT, MAX_RELAY, MAX_TEXT, NAME,
        PeerAddr, decode_bytes, encode, fingerprint, plain,
    };

    /// `value` written as a text of kind `x`, if it can be.
    fn written(value: &[u8]) -> Option<String> {
        struct Shown<'a>(&'a [u8]);
        impl fmt::Display for Shown<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                encode("x", &self.0, f)
            }
        }
        let mut text = String::new();
        fmt::write(&mut text, format_args!("{}", Shown(value))).ok()?;
        Some(text)
    }

    /// What is written is encoded within what a text carries, or not at
    /// all: nothing larger is made to be written.
    #[test]
    fn a_value_past_a_texts_bytes_is_not_written() {
        // Its length takes two bytes of postcard.
        let most = MAX_BYTES - 2;
        let text = written(&vec![3; most]).unwrap();
        assert!(text.len() <= 1 + MAX_TEXT, "{}", text.len());
        assert_eq!(decode_bytes("x", &text).unwrap().len(), MAX_BYTES);
        assert_eq!(written(&vec![3; most + 1]), None);
    }

    /// The largest ticket there is reads back; one character more of its
    /// kind's text is refused unread.
    #[test]
    fn the_largest_ticket_is_within_the_text_bound() {
        let host = Identity::ephemeral().unwrap();
        let direct = (0..MAX_DIRECT)
            .map(|at| {
                format!("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:{at:x}]:65535")
                    .parse()
                    .unwrap()
            })
            .collect();
        let ticket = JoinTicket {
            v: 1,
            host: PeerAddr {
                id: host.public(),
                relay: Some(Text::truncated(&"r".repeat(MAX_RELAY))),
                direct: Bounded::truncated(direct),
            },
            owner: host.public(),
            project: ProjectId([0xff; 16]),
            invite: [0xff; 16],
            flags: 0xff,
            arch: Some(Text::truncated(&"a".repeat(MAX_ARCH))),
        };
        let text = ticket.to_string();
        assert!(text.len() - "binbun".len() <= MAX_TEXT, "{}", text.len());
        assert_eq!(text.parse::<JoinTicket>().unwrap(), ticket);
        let card = Card::new(&host, &"\u{1f600}".repeat(NAME)).to_string();
        assert!(card.len() - "binbunid".len() <= MAX_TEXT);
        let over = format!("binbun{}", "a".repeat(MAX_TEXT + 1));
        assert!(decode_bytes("binbun", &over).is_err());
        assert!(decode_bytes("binbun", &over[..over.len() - 1]).is_ok());
    }

    #[test]
    fn a_card_naming_its_holder_with_controls_or_at_length_is_refused_however_signed() {
        let who = Identity::ephemeral().unwrap();
        // Signed by its key as any card is, but not by `Card::new`.
        let signed = |name: &str| {
            let signer = SigningKey::from_bytes(&who.secret());
            Card {
                key: who.public(),
                agreement: who.agreement(),
                name: Text::try_from(name).unwrap(),
                sig: signer.sign(&Card::signed(who.public(), &who.agreement(), name)),
            }
        };
        assert!(signed("Ann").verifies());
        assert!(signed(&"a".repeat(NAME)).verifies());
        for name in [
            "a".repeat(NAME + 1),
            "Ann\u{1b}[2J".to_owned(),
            "Ann\nOwner".to_owned(),
            "\u{202e}nnA".to_owned(),
            "An\u{200b}n".to_owned(),
            "Ann\u{e0041}".to_owned(),
            "Ann\u{2028}".to_owned(),
        ] {
            let card = signed(&name);
            assert!(!card.verifies(), "{name:?} taken");
            assert!(card.to_string().parse::<Card>().is_err(), "{name:?} read");
        }
        // Made by the constructor, such a name loses what is refused.
        let made = Card::new(&who, "\u{202e}A\u{1b}nn\u{200b} \u{fe0f}é");
        assert_eq!(made.name, "Ann \u{fe0f}é");
        assert!(made.verifies());
        assert!(plain("Ann é", 5) && !plain("Ann é", 4));
    }

    #[test]
    fn tickets_and_cards_read_back_and_refuse_what_they_are_not() {
        let host = Identity::ephemeral().unwrap();
        let ticket = JoinTicket {
            v: 1,
            host: PeerAddr {
                id: host.public(),
                relay: Some(Text::truncated("https://relay.example./")),
                direct: Bounded::truncated(vec!["192.168.1.5:4433".parse().unwrap()]),
            },
            owner: host.public(),
            project: ProjectId([6; 16]),
            invite: [7; 16],
            flags: LAN_ONLY,
            arch: None,
        };
        let text = ticket.to_string();
        assert!(
            text.starts_with("binbun")
                && text
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        assert_eq!(text.parse::<JoinTicket>().unwrap(), ticket);
        assert_eq!(
            text.to_ascii_uppercase()
                .replacen("BINBUN", "binbun", 1)
                .parse::<JoinTicket>()
                .unwrap(),
            ticket
        );
        // All upper case, as a QR code's alphanumeric mode carries it.
        assert_eq!(
            text.to_ascii_uppercase().parse::<JoinTicket>().unwrap(),
            ticket
        );
        assert!(text[..text.len() - 3].parse::<JoinTicket>().is_err());
        assert!(ticket.lan_only());
        let mut later = ticket;
        later.v = 2;
        assert!(later.to_string().parse::<JoinTicket>().is_err());

        let card = Card::new(&host, "Ann");
        let card_text = card.to_string();
        assert_eq!(card_text.parse::<Card>().unwrap(), card);
        assert!(card_text.parse::<JoinTicket>().is_err());
        assert!(text.parse::<Card>().is_err());
        // A card whose name was changed no longer verifies.
        let mut renamed = card;
        renamed.name = Text::truncated("Bob");
        assert!(renamed.to_string().parse::<Card>().is_err());

        let print = fingerprint(host.public());
        assert_eq!(print.len(), 24);
        assert_eq!(print.split(' ').count(), 5);
        assert_ne!(print, fingerprint(Identity::ephemeral().unwrap().public()));
    }

    #[test]
    fn tickets_with_and_without_a_slice_read_back() {
        let host = Identity::ephemeral().unwrap();
        let addr = PeerAddr {
            id: host.public(),
            relay: None,
            direct: Bounded::truncated(vec!["10.0.0.2:4433".parse().unwrap()]),
        };
        let plain = JoinTicket {
            v: 1,
            host: addr,
            owner: host.public(),
            project: ProjectId([9; 16]),
            invite: [2; 16],
            flags: 0,
            arch: None,
        };
        let sliced = JoinTicket {
            arch: Some(Text::truncated("arm64e")),
            ..plain.clone()
        };
        for ticket in [&plain, &sliced] {
            let text = ticket.to_string();
            assert_eq!(&text.parse::<JoinTicket>().unwrap(), ticket);
            assert_eq!(
                &text.to_ascii_uppercase().parse::<JoinTicket>().unwrap(),
                ticket
            );
        }
        let read: JoinTicket = sliced.to_string().parse().unwrap();
        assert_eq!(read.arch.as_deref(), Some("arm64e"));
        // A slice cut short does not read.
        let text = sliced.to_string();
        assert!(text[..text.len() - 2].parse::<JoinTicket>().is_err());
    }
}
