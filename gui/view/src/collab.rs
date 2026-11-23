//! Collaboration as the window shows it, without the network (the app's
//! `collab` feature brings
//! that): who is in the session and how far each is trusted, their
//! avatars, where their cursors are and whom this window follows, the
//! session's chat, the conflicts and refusals as cards, the banner of an
//! analysis that differs from a peer's (and its debug file, to get from
//! them), and files a peer offers ([`Offered`]) as they come
//! ([`Fetching`]).
//!
//! - **Trust on first use** ([`Known`]): the identities the owner admitted
//!   to a shared project are kept beside its membership chain
//!   (`<project>/collab/<project id>/known.toml`), with the names each
//!   used. A joiner is judged against them ([`Known::judge`]): known,
//!   known under another name, new, or an **impostor**: a new key whose
//!   name looks like a known person's ([`skeleton`]). An impostor is
//!   never admitted without asking ([`admits_unasked`]).
//! - **Avatars** ([`Colours::avatar`]): initials on a colour of a fixed
//!   palette, each member's own in the session, kept apart from the
//!   others' hues, and the same on every peer ([`Colours`]).
//! - **Follow mode** ([`Follow`]): the leader's cursor, each time it
//!   moves, is where this window goes, until the user moves themselves.
//! - **Members by card** ([`listed_members`], [`card_text`],
//!   [`card_refused`]): the owner's Members row lists the membership
//!   chain's members and adds one from their identity card (`binbunid…`),
//!   so they can join through any member linked, with an ordinary ticket.
//! - **Approvals** ([`Approvals`]): the requests to join waiting, each by
//!   its id; an answer takes the request its card showed, by that id, or
//!   nothing if it has gone.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use binbun_session::Conflict;
use binbun_session::journal::{EngineVersion, Key, PublicKey, Value};
use jiff::tz::TimeZone;
use jiff::{Timestamp, Zoned};
use toml_edit::{Array, DocumentMut, Item, Table, value};

use crate::agents::{self, Agent, Face};
use crate::banners::{Action, Banner, Button, Kind, Priority, Tone};
use crate::chat::ChatLink;

/// `key`'s fingerprint, to compare by voice: 20 hexadecimal digits
/// of its BLAKE3, in groups of 4 (as `binbun id` prints it).
pub fn fingerprint(key: PublicKey) -> String {
    let hash = blake3::hash(&key.0);
    let mut hex = String::with_capacity(24);
    for (i, byte) in hash.as_bytes().iter().take(10).enumerate() {
        if i > 0 && i % 2 == 0 {
            hex.push(' ');
        }
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// A participant's avatar: their initials on their colour (an agent's
/// face instead of initials).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Avatar {
    /// One or two letters: the first of the name's first two words.
    pub initials: String,
    /// Their colour: its place in the palette ([`avatar_rgb`]).
    pub slot: usize,
    /// An agent's face: its harness's mark, or the Bot glyph.
    pub agent: Option<Face>,
}

/// How many colours avatars take: hues told apart at a glance.
pub const PALETTE: usize = 10;

/// The avatars' colours (`0xRRGGBB`) on a light theme: deep enough to
/// stand out on white, each keeping [`AVATAR_INK`] at an APCA contrast
/// of Lc 55 or more. Red, orange, amber, green, teal, cyan, blue, violet,
/// purple, pink.
const LIGHT: [u32; PALETTE] = [
    0x00d2_3434,
    0x00e0_701a,
    0x00b0_8400,
    0x004c_9a1f,
    0x0012_957a,
    0x000e_8fb8,
    0x002f_6fe0,
    0x006a_4fdc,
    0x00a4_3fc9,
    0x00c9_307f,
];

/// The same hues on a dark theme: light enough to stand out on it, deep
/// enough to keep [`AVATAR_INK`] at Lc 55 or more.
const DARK: [u32; PALETTE] = [
    0x00f2_6b6b,
    0x00f3_842b,
    0x00c4_9d17,
    0x006f_b337,
    0x0038_b495,
    0x0023_aedb,
    0x006d_9cf5,
    0x009a_85f2,
    0x00c9_7ae6,
    0x00f0_6aa8,
];

/// The slot `key` would have alone: from its hash, the same everywhere.
fn preferred(key: PublicKey) -> usize {
    let hash = blake3::hash(&key.0);
    let [a, b, ..] = *hash.as_bytes();
    usize::from(u16::from_le_bytes([a, b])) % PALETTE
}

/// How many places apart around the palette two members' slots must be
/// to tell them apart at a glance: neighbouring hues (red and orange,
/// pink and red) are too alike.
const SEPARATION: usize = 2;

/// How many places apart slots `a` and `b` are around the palette (it
/// wraps: pink is beside red).
fn apart(a: usize, b: usize) -> usize {
    let d = a.abs_diff(b) % PALETTE;
    d.min(PALETTE - d)
}

/// Who has which colour in a shared project: what every peer works out
/// alike from the same members, whatever order it has them in
/// ([`Colours::of`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Colours {
    /// Each member's slot.
    slots: BTreeMap<PublicKey, usize>,
    /// Each slot's last holder's place in the order slots were given
    /// (`None`: free).
    given: [Option<usize>; PALETTE],
}

impl Colours {
    /// The colours of `members` (in any order, repeats ignored: every peer
    /// with the same members works out the same). A member whose key's
    /// slot ([`preferred`]) is [`SEPARATION`] or more places from every
    /// other member's keeps it. The rest, by key, each take the free slot
    /// nearest their key's that is [`SEPARATION`] or more places from
    /// every slot given (nearer clockwise at a tie); with none so far
    /// apart, the nearest free one; with every slot taken, the one given
    /// first. So a member's colour changes when others join or leave only
    /// if their key's slot, or the one they were moved to, is too near
    /// another's; no two share one until more than [`PALETTE`] are
    /// members.
    pub fn of(members: &[PublicKey]) -> Self {
        let keys: BTreeMap<PublicKey, usize> =
            members.iter().map(|&key| (key, preferred(key))).collect();
        let clear = |key: &PublicKey, own: usize| {
            keys.iter()
                .all(|(other, &theirs)| other == key || apart(own, theirs) >= SEPARATION)
        };
        let (alone, clashing): (Vec<_>, Vec<_>) =
            keys.iter().partition(|&(key, &own)| clear(key, own));
        let mut colours = Self::default();
        for (n, (&key, _)) in alone.into_iter().chain(clashing).enumerate() {
            let slot = colours.next(key);
            colours.slots.insert(key, slot);
            if let Some(given) = colours.given.get_mut(slot) {
                *given = Some(n);
            }
        }
        colours
    }

    /// Whether `slot` is [`SEPARATION`] or more places from every slot
    /// given.
    fn far(&self, slot: usize) -> bool {
        self.given
            .iter()
            .enumerate()
            .all(|(other, given)| given.is_none() || apart(slot, other) >= SEPARATION)
    }

    /// The slot `key` takes after the members given theirs ([`Self::of`]).
    fn next(&self, key: PublicKey) -> usize {
        let own = preferred(key);
        // The slots nearest `own` first, clockwise before anticlockwise.
        let nearest = (0..=PALETTE / 2)
            .flat_map(|step| [own + step, own + PALETTE - step])
            .map(|slot| slot % PALETTE);
        let free = |slot: &usize| self.given.get(*slot).is_some_and(Option::is_none);
        nearest
            .clone()
            .find(|slot| free(slot) && self.far(*slot))
            .or_else(|| nearest.clone().find(free))
            .or_else(|| (0..PALETTE).min_by_key(|&slot| self.given.get(slot).copied().flatten()))
            .unwrap_or(own)
    }

    /// `key`'s slot: a member's own; someone not a member (yet), the one
    /// they would take after the members.
    pub fn slot(&self, key: PublicKey) -> usize {
        self.slots
            .get(&key)
            .copied()
            .unwrap_or_else(|| self.next(key))
    }

    /// The avatar of `key` named `name`.
    pub fn avatar(&self, key: PublicKey, name: &str) -> Avatar {
        let initials: String = name
            .split_whitespace()
            .filter_map(|word| word.chars().next())
            .take(2)
            .flat_map(char::to_uppercase)
            .collect();
        Avatar {
            initials: if initials.is_empty() {
                "?".to_owned()
            } else {
                initials
            },
            slot: self.slot(key),
            agent: None,
        }
    }

    /// The avatar of agent `key` named `name`: its face on its colour.
    pub fn agent_avatar(&self, key: PublicKey, name: &str) -> Avatar {
        Avatar {
            agent: Some(agents::face(name)),
            ..self.avatar(key, name)
        }
    }
}

/// `name` as it looks (a confusable skeleton, case-folded, after UTS
/// #39 in a small form): lower case, accents and spaces dropped, and the
/// letters people mistake for one another (Cyrillic and Greek look-alikes,
/// `0`/`o`, `1`/`l`/`I`, `rn`/`m`, `vv`/`w`, `cl`/`d`) made one. Case
/// folded, `I` is `i`, so `i` is taken for `l` too. Characters that show
/// nothing ([`invisible`]) are dropped, before the look-alike pairs are.
pub fn skeleton(name: &str) -> String {
    let mut out = String::new();
    for c in name
        .chars()
        .filter(|c| !invisible(*c))
        .flat_map(char::to_lowercase)
    {
        let mapped = match c {
            'а' | 'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'α' | '@' => 'a',
            'ь' | 'в' | 'β' => 'b',
            'с' | 'ç' | 'ϲ' => 'c',
            'ԁ' => 'd',
            'е' | 'è' | 'é' | 'ê' | 'ë' | 'ε' | 'є' => 'e',
            'ɡ' => 'g',
            'һ' => 'h',
            'i' | 'і' | 'ì' | 'í' | 'î' | 'ï' | 'ι' | 'ı' | '1' | '|' | 'ӏ' | 'ǀ' => 'l',
            'ј' => 'j',
            'κ' | 'к' => 'k',
            'ñ' | 'η' => 'n',
            'о' | 'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ο' | 'σ' | '0' => 'o',
            'р' | 'ρ' => 'p',
            'ԛ' => 'q',
            'ѕ' | '$' => 's',
            'τ' | 'т' => 't',
            'υ' | 'ù' | 'ú' | 'û' | 'ü' | 'μ' => 'u',
            'ν' => 'v',
            'ԝ' | 'ω' => 'w',
            'х' | 'χ' => 'x',
            'у' | 'ý' | 'ÿ' | 'γ' => 'y',
            'ᴢ' => 'z',
            c if c.is_whitespace() || matches!(c, '_' | '-' | '.' | '\'') => {
                continue;
            }
            c => c,
        };
        out.push(mapped);
    }
    out.replace("rn", "m").replace("vv", "w").replace("cl", "d")
}

/// Whether `c` shows nothing of its own: a control character (`Cc`), a
/// format character (`Cf`: bidirectional controls, zero-width spaces and
/// joiners, tags, the soft hyphen), a variation selector, the combining
/// grapheme joiner or a Hangul filler.
pub fn invisible(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{ad}'
                | '\u{34f}'
                | '\u{600}'..='\u{605}'
                | '\u{61c}'
                | '\u{6dd}'
                | '\u{70f}'
                | '\u{890}'..='\u{891}'
                | '\u{8e2}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
                | '\u{e0100}'..='\u{e01ef}'
        )
}

/// `name` as shown and traced: each character that shows nothing
/// ([`invisible`]) written as its code point (`\u{202e}`), so none reorders,
/// hides or rewrites what is around it (on screen or in a terminal).
pub fn shown_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if invisible(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// How far a joiner is trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trust {
    /// Admitted before: this key, under this name (or `was`: under
    /// another before).
    Known {
        /// The name it used last, if not this one.
        was: Option<String>,
    },
    /// Never seen, and no one like them known.
    New,
    /// A new key under a name that looks like `like`'s, a known person
    /// (another key): possibly not who they say.
    Impostor {
        /// The known person's name.
        like: String,
    },
}

/// How a known identity was checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verified {
    /// Trusted on first use.
    Tofu,
    /// Fingerprints compared by hand.
    Compared,
}

/// An identity admitted before.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownPerson {
    /// The names it used, oldest first.
    pub names: Vec<String>,
    /// When it was first admitted (Unix seconds).
    pub first: u64,
    /// When it was last seen (Unix seconds).
    pub last: u64,
    /// How it was checked.
    pub verified: Verified,
}

/// The identities admitted to a shared project, kept in its
/// `known.toml`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Known {
    path: Option<PathBuf>,
    people: BTreeMap<PublicKey, KnownPerson>,
}

/// A key's hexadecimal.
pub(crate) fn hex(key: PublicKey) -> String {
    key.0.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The key `text` writes in hexadecimal.
pub(crate) fn unhex(text: &str) -> Option<PublicKey> {
    let mut key = [0; 32];
    if text.len() != 64 {
        return None;
    }
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(PublicKey(key))
}

impl Known {
    /// Where shared project `project`'s known identities are kept in the
    /// project directory `dir`.
    pub fn path_in(dir: &Path, project: &str) -> PathBuf {
        dir.join("collab").join(project).join("known.toml")
    }

    /// Those kept at `path` (none if there is no file, or it does not
    /// read); saved there.
    pub fn load(path: PathBuf) -> Self {
        let mut people = BTreeMap::new();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let document = text.parse::<DocumentMut>().unwrap_or_default();
        if let Some(list) = document.get("person").and_then(Item::as_array_of_tables) {
            for table in list {
                let Some(key) = table.get("key").and_then(Item::as_str).and_then(unhex) else {
                    continue;
                };
                let names = table
                    .get("names")
                    .and_then(Item::as_array)
                    .map(|names| {
                        names
                            .iter()
                            .filter_map(|n| n.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                let time = |field| {
                    table
                        .get(field)
                        .and_then(Item::as_integer)
                        .and_then(|n| u64::try_from(n).ok())
                        .unwrap_or(0)
                };
                let verified = match table.get("verified").and_then(Item::as_str) {
                    Some("compared") => Verified::Compared,
                    _ => Verified::Tofu,
                };
                people.insert(
                    key,
                    KnownPerson {
                        names,
                        first: time("first"),
                        last: time("last"),
                        verified,
                    },
                );
            }
        }
        Self {
            path: Some(path),
            people,
        }
    }

    /// The identities kept.
    pub fn people(&self) -> &BTreeMap<PublicKey, KnownPerson> {
        &self.people
    }

    /// How far `key` asking as `name` is trusted, among those kept and
    /// `others` (the participants now and this peer: a key and a name).
    pub fn judge(&self, key: PublicKey, name: &str, others: &[(PublicKey, String)]) -> Trust {
        if let Some(known) = self.people.get(&key) {
            let was = known.names.last().filter(|last| *last != name).cloned();
            return Trust::Known { was };
        }
        let look = skeleton(name);
        let kept = self
            .people
            .iter()
            .flat_map(|(k, person)| person.names.iter().map(move |n| (*k, n.as_str())));
        let others = others.iter().map(|(k, n)| (*k, n.as_str()));
        kept.chain(others)
            .find(|(k, n)| *k != key && !look.is_empty() && skeleton(n) == look)
            .map_or(Trust::New, |(_, like)| Trust::Impostor {
                like: like.to_owned(),
            })
    }

    /// Keeps `key` as admitted under `name` at `now` (Unix seconds).
    pub fn admit(&mut self, key: PublicKey, name: &str, now: u64) {
        let person = self.people.entry(key).or_insert_with(|| KnownPerson {
            names: Vec::new(),
            first: now,
            last: now,
            verified: Verified::Tofu,
        });
        if person.names.last().is_none_or(|last| last != name) {
            person.names.push(name.to_owned());
        }
        person.last = now;
    }

    /// Marks `key`'s fingerprint compared by hand.
    pub fn compared(&mut self, key: PublicKey) {
        if let Some(person) = self.people.get_mut(&key) {
            person.verified = Verified::Compared;
        }
    }

    /// Writes them back where they were read.
    ///
    /// # Errors
    ///
    /// The file cannot be written.
    pub fn save(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut document = DocumentMut::new();
        let mut list = toml_edit::ArrayOfTables::new();
        for (key, person) in &self.people {
            let mut table = Table::new();
            table.insert("key", value(hex(*key)));
            let mut names = Array::new();
            for name in &person.names {
                names.push(name.as_str());
            }
            table.insert("names", value(names));
            table.insert("first", value(i64::try_from(person.first).unwrap_or(0)));
            table.insert("last", value(i64::try_from(person.last).unwrap_or(0)));
            table.insert(
                "verified",
                value(match person.verified {
                    Verified::Tofu => "tofu",
                    Verified::Compared => "compared",
                }),
            );
            list.push(table);
        }
        document.insert("person", Item::ArrayOfTables(list));
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let text = format!(
            "# The identities admitted to this shared project, trusted on first use.\n{document}"
        );
        std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// Whether a joiner judged `trust` is admitted without asking: only one
/// known before, and only when the host said so (`known`); an impostor
/// never.
pub fn admits_unasked(trust: &Trust, known: bool) -> bool {
    match trust {
        Trust::Known { was: None } => known,
        Trust::Known { was: Some(_) } | Trust::New | Trust::Impostor { .. } => false,
    }
}

/// The requests to join waiting for an answer, in the order they came,
/// each by its id (unique, never given again): each one's card shows,
/// and its buttons answer it by the id it was drawn with.
#[derive(Clone, Debug)]
pub struct Approvals<T> {
    waiting: VecDeque<(u64, T)>,
}

impl<T> Default for Approvals<T> {
    fn default() -> Self {
        Self {
            waiting: VecDeque::new(),
        }
    }
}

impl<T> Approvals<T> {
    /// Adds request `id`, after those waiting.
    pub fn push(&mut self, id: u64, request: T) {
        self.waiting.push_back((id, request));
    }

    /// The requests waiting, in the order they came, each with its id.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &T)> {
        self.waiting.iter().map(|(id, request)| (*id, request))
    }

    /// Takes request `id` to answer it: `None` if it has gone (withdrawn,
    /// answered), and then nothing is answered.
    pub fn take(&mut self, id: u64) -> Option<T> {
        let at = self
            .waiting
            .iter()
            .position(|(waiting, _)| *waiting == id)?;
        self.waiting.remove(at).map(|(_, request)| request)
    }

    /// How many wait.
    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    /// Whether none waits.
    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }

    /// Forgets them all (the session over).
    pub fn clear(&mut self) {
        self.waiting.clear();
    }
}

/// What the approval card says of `trust` for `name`, and whether it is
/// a warning (red); each name as shown ([`shown_name`]).
pub fn trust_text(trust: &Trust, name: &str) -> (String, bool) {
    let name = shown_name(name);
    match trust {
        Trust::Known { was: None } => (format!("{name}, admitted before with this key"), false),
        Trust::Known { was: Some(was) } => (
            format!(
                "{name} (was {}), admitted before with this key",
                shown_name(was)
            ),
            false,
        ),
        Trust::New => ("New key: compare the fingerprint".to_owned(), false),
        Trust::Impostor { like } => (
            format!(
                "Not the {} you know (a new key): compare the fingerprint",
                shown_name(like)
            ),
            true,
        ),
    }
}

/// Where in the binary a participant's cursor is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Place {
    /// The listing.
    Listing,
    /// A function's C: its entry, the view, the line.
    C {
        /// The function's entry.
        function: u64,
        /// The reading view (else the exact one).
        reading: bool,
        /// The line.
        line: u32,
    },
    /// The hex view.
    Hex,
    /// A function's graph.
    Graph {
        /// The function's entry.
        function: u64,
    },
    /// A list of cross-references.
    Xrefs,
}

/// A participant's cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cursor {
    /// Where.
    pub place: Place,
    /// Its address.
    pub address: u64,
    /// Its column on its line, in characters (on the listing's line in
    /// the listing, on the C line in the C): where its caret goes.
    pub column: u32,
    /// What is selected, if anything.
    pub selection: Option<Selection>,
}

/// A participant's selection, in their view's units.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Selection {
    /// Addresses: the items of the listing's lines selected, the hex
    /// view's bytes (the first and the last).
    Addresses {
        /// The first.
        first: u64,
        /// The last.
        last: u64,
    },
    /// The C's text on the cursor's function and view: from a line and
    /// column to another, in characters, the end excluded.
    Text {
        /// Where it starts: line, column.
        from: (u32, u32),
        /// Where it ends: line, column.
        to: (u32, u32),
    },
}

/// A role, as shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// The project's owner.
    Owner,
    /// Reads and edits.
    Editor,
    /// Reads only.
    Viewer,
    /// A role the membership format reserves: nothing links with it.
    Store,
    /// An agent: edits as an editor does.
    Agent,
}

impl Role {
    /// Its name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Editor => "editor",
            Self::Viewer => "viewer",
            Self::Store => "store",
            Self::Agent => "agent",
        }
    }
}

/// The members a shared project's Members row lists, from its membership
/// chain's `admitted` (each key and its role now, `None` once removed):
/// those not removed, in the order admitted (the owner first).
pub fn listed_members(admitted: &[(PublicKey, Option<Role>)]) -> Vec<(PublicKey, Role)> {
    admitted
        .iter()
        .filter_map(|&(key, role)| Some((key, role?)))
        .collect()
}

/// What a text pasted as an identity card is instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotCard {
    /// Nothing.
    Empty,
    /// A join ticket (`binbun…`).
    Ticket,
    /// Nothing of binbun's.
    Other,
}

impl NotCard {
    /// As the Members row says it.
    pub fn text(self) -> &'static str {
        match self {
            Self::Empty => "No identity card",
            Self::Ticket => "A ticket, not an identity card",
            Self::Other => "Not an identity card",
        }
    }
}

/// The identity card pasted as `text`, without the whitespace a paste
/// may carry (a wrapped line too); else what it is instead.
///
/// # Errors
///
/// Empty; another kind of binbun text; nothing of binbun's.
pub fn card_text(text: &str) -> Result<String, NotCard> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let lower = text.to_ascii_lowercase();
    // The longer prefix first: a ticket starts with `binbun` too.
    if text.is_empty() {
        Err(NotCard::Empty)
    } else if lower.starts_with("binbunid") {
        Ok(text)
    } else if lower.starts_with("binbun") {
        Err(NotCard::Ticket)
    } else {
        Err(NotCard::Other)
    }
}

/// Why an identity card is not added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardRefused {
    /// It is one's own.
    Own,
    /// Its key is a member's now.
    Member,
}

/// Why the card of `key` is not added by `me` to a project whose members
/// are `members` (as listed), if it is not. One removed is admitted
/// again.
pub fn card_refused(
    key: PublicKey,
    me: PublicKey,
    members: &[(PublicKey, Role)],
) -> Option<CardRefused> {
    if key == me {
        Some(CardRefused::Own)
    } else if members.iter().any(|&(member, _)| member == key) {
        Some(CardRefused::Member)
    } else {
        None
    }
}

/// A participant's analysis.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Analysis {
    /// The analysis fingerprint.
    pub fingerprint: [u8; 32],
    /// The debug file read: its name and SHA-256.
    pub debug: Option<(String, [u8; 32])>,
}

/// Someone else in the session.
#[derive(Clone, Debug, PartialEq)]
pub struct Person {
    /// Their identity key.
    pub key: PublicKey,
    /// Their name.
    pub name: String,
    /// Their binbun.
    pub engine: EngineVersion,
    /// Their analysis, once told.
    pub analysis: Option<Analysis>,
    /// Their cursor, unless stale.
    pub cursor: Option<Cursor>,
    /// Whom they follow.
    pub following: Option<PublicKey>,
    /// Their role, as the membership chain says.
    pub role: Option<Role>,
    /// How this peer's link reaches them (none: through the host).
    pub path: Option<String>,
    /// Why they are view-only in this session (another build than the
    /// host's: the host's link says so), if they are.
    pub view_only: Option<String>,
    /// What they say of themselves if they are an agent.
    pub agent: Option<Agent>,
}

impl Person {
    /// Their avatar, in their colour of `colours`.
    pub fn avatar(&self, colours: &Colours) -> Avatar {
        if self.agent.is_some() {
            colours.agent_avatar(self.key, &self.name)
        } else {
            colours.avatar(self.key, &self.name)
        }
    }

    /// Their version, and whether it is another build than `mine` (they
    /// are view-only in this session).
    pub fn version(&self, mine: &EngineVersion) -> (String, bool) {
        let build = if self.engine.build.is_empty() {
            String::new()
        } else {
            format!(" ({})", self.engine.build)
        };
        (
            format!("binbun {}{build}", self.engine.release),
            self.engine != *mine,
        )
    }
}

/// One chat message, as shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatLine {
    /// Its id (the live session's: what the owner's removal names).
    pub id: u64,
    /// Its author.
    pub from: PublicKey,
    /// Their name (or a fingerprint's start, if unknown).
    pub name: String,
    /// When: Unix milliseconds.
    pub time: u64,
    /// The text.
    pub text: String,
    /// Whether the owner removed it (its text gone).
    pub removed: bool,
    /// The places its text names, as its author resolved them.
    pub links: Vec<ChatLink>,
    /// Whom it @mentions.
    pub mentions: Vec<PublicKey>,
}

/// The colour of palette slot `slot` (any number: taken modulo
/// [`PALETTE`]) on a dark theme or a light one, as `0xRRGGBB`.
pub fn avatar_rgb(slot: usize, dark: bool) -> u32 {
    let palette = if dark { &DARK } else { &LIGHT };
    palette.get(slot % PALETTE).copied().unwrap_or_default()
}

/// WCAG relative luminance of an sRGB colour (`0xRRGGBB`).
pub(crate) fn luminance(rgb: u32) -> f32 {
    let lin = |shift: u32| {
        let v = f32::from(u8::try_from((rgb >> shift) & 0xff).unwrap_or(u8::MAX)) / 255.0;
        if v <= 0.040_45 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * lin(16) + 0.7152 * lin(8) + 0.0722 * lin(0)
}

/// The ink (`0xRRGGBB`) of avatars' initials and single-colour marks, on
/// every colour of both palettes: white, which each keeps at an APCA
/// contrast of Lc 55 or more.
pub const AVATAR_INK: u32 = 0x00ff_ffff;

/// The font size and the capitals' height of `letters` initials on an
/// avatar `diameter` device pixels across, in a font whose capitals are
/// `cap_per_size` of its size: about half the diameter for one letter
/// (0.42 for two), adjusted so the capitals' height is a whole number of
/// pixels with the diameter's parity. Centred on the circle (their
/// baseline at its centre plus half that height), they then start and end
/// on pixel edges as the circle does: glyphs are placed on whole device
/// pixels down, and hinting makes the capitals' height a whole number.
pub fn initials_size(diameter: f32, cap_per_size: f32, letters: usize) -> (f32, f32) {
    let d = diameter.round();
    let want = diameter * cap_per_size * if letters > 1 { 0.42 } else { 0.525 };
    let mut cap = ((want - d) / 2.0).round().mul_add(2.0, d);
    if cap < 1.0 {
        cap += 2.0;
    }
    (cap / cap_per_size, cap)
}

/// A link's path as the status bar says it: the path in use, direct (on
/// a tailnet, or within this machine: `loopback`) or by relay, and its
/// round trip, never an address: `direct 0.5 ms`. `path`
/// is the transport's (`*direct 192.168.1.5:4433 (0.5 ms), relay https://…
/// (31.0 ms)`, the one in use starred).
pub fn link_text(path: &str) -> String {
    let paths: Vec<&str> = path.split(", ").collect();
    let chosen = paths
        .iter()
        .find(|p| p.starts_with('*'))
        .or_else(|| paths.first())
        .map_or("", |p| p.trim_start_matches('*'));
    let kind = if chosen.starts_with("relay") {
        "relay"
    } else if chosen.starts_with("direct") {
        if chosen.contains("(loopback)") {
            "loopback"
        } else if chosen.contains("(tailnet)") {
            "tailnet"
        } else {
            "direct"
        }
    } else if chosen == "in memory" {
        return "in memory".to_owned();
    } else {
        return "connecting".to_owned();
    };
    let rtt = chosen
        .rsplit_once('(')
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .filter(|rtt| rtt.ends_with(" ms"));
    match rtt {
        Some(rtt) => format!("{kind} {rtt}"),
        None => kind.to_owned(),
    }
}

/// Stop sharing's question while `names` are linked: "Stop sharing? Bob
/// will be disconnected." (`None`: no one is, nothing to ask).
pub fn stop_text(names: &[String]) -> Option<String> {
    let who = match names {
        [] => return None,
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    Some(format!("Stop sharing? {who} will be disconnected."))
}

/// The most avatars the title bar stacks; more, and the last place is a
/// "+N" chip (the session's popover lists everyone).
pub const STACK: usize = 4;

/// The avatars to stack of `order` (as they came, newest last), at most
/// [`STACK`]: all if they fit, else the newest `STACK - 1` and a chip for
/// the rest, the followed person (`leader`) always among those shown.
/// Returns the keys shown, in order, and how many the chip stands for.
pub fn stack(order: &[PublicKey], leader: Option<PublicKey>) -> (Vec<PublicKey>, usize) {
    if order.len() <= STACK {
        return (order.to_vec(), 0);
    }
    let newest = order.len() - (STACK - 1);
    let mut shown: Vec<PublicKey> = order.iter().skip(newest).copied().collect();
    if let Some(leader) = leader.filter(|l| !shown.contains(l) && order.contains(l)) {
        // The oldest shown makes way; the followed one goes first (the
        // oldest of those shown).
        shown.remove(0);
        shown.insert(0, leader);
    }
    let hidden = order.len() - shown.len();
    (shown, hidden)
}

/// Where someone is, as the session's popover and their card say it:
/// `push_stream · 1E720 · C`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Whereabouts {
    /// The function their cursor is in, as shown (none outside one).
    pub function: Option<String>,
    /// Their address, in hexadecimal (`1E720`).
    pub address: String,
    /// The view they are in: `listing`, `C`, `graph`, `hex`, `xrefs`.
    pub view: &'static str,
}

impl Whereabouts {
    /// `cursor`'s place, in `function` (its name as shown) if in one.
    pub fn of(cursor: &Cursor, function: Option<String>) -> Self {
        Self {
            function,
            address: format!("{:X}", cursor.address),
            view: match cursor.place {
                Place::Listing => "listing",
                Place::C { .. } => "C",
                Place::Graph { .. } => "graph",
                Place::Hex => "hex",
                Place::Xrefs => "xrefs",
            },
        }
    }

    /// Its text in one line: `push_stream · 1E720 · C` (`1E720 · hex`
    /// outside a function).
    pub fn text(&self) -> String {
        match &self.function {
            Some(function) => format!("{function} \u{b7} {} \u{b7} {}", self.address, self.view),
            None => format!("{} \u{b7} {}", self.address, self.view),
        }
    }
}

/// The tops of others' ticks on a map strip `height` long, from where
/// each one's address puts it (`at`, its top, in order of `at`'s people):
/// each at least `spacing` below the one above (ticks at nearly the same
/// spot stay apart, never merged), the last kept `spacing` from the
/// strip's end, none above its start.
pub fn spread_ticks(at: &[f32], spacing: f32, height: f32) -> Vec<f32> {
    let mut tops: Vec<(usize, f32)> = at.iter().copied().enumerate().collect();
    tops.sort_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)));
    let mut previous = f32::NEG_INFINITY;
    for (_, top) in &mut tops {
        *top = top.max(previous + spacing).max(0.0);
        previous = *top;
    }
    // Pushed past the end: back up from it, as far as the start allows.
    let mut next = height;
    for (_, top) in tops.iter_mut().rev() {
        *top = top.min(next - spacing).max(0.0);
        next = *top;
    }
    tops.sort_by_key(|&(i, _)| i);
    tops.into_iter().map(|(_, top)| top).collect()
}

/// What a peer's change did, short, for the status bar: "Bob renamed
/// v15 → fd". `edits` are its keys with their values and those before
/// ([`binbun_session::Session::edits_of`]); `engine_name` is the name the
/// engine gives a key the user never named (`v15`, `g_1299a8`), if known.
/// Each name and the label are escaped ([`shown_name`]) before the line is
/// put together: a peer wrote them.
pub fn change_text(
    who: &str,
    label: &str,
    edits: &[(Key, Value, Value)],
    engine_name: &dyn Fn(&Key) -> Option<String>,
) -> String {
    let (who, label) = (shown_name(who), shown_name(label));
    let [(key, Value::Text(after), Value::Text(before))] = edits else {
        return format!("{who}: {label}");
    };
    match key {
        Key::FunctionName(_) | Key::GlobalName(_) | Key::VariableName(_) | Key::Slot(..) => {
            let old = before.clone().or_else(|| engine_name(key));
            match (
                old.as_deref().map(shown_name),
                after.as_deref().map(shown_name),
            ) {
                (Some(old), Some(new)) => format!("{who} renamed {old} → {new}"),
                (None, Some(new)) => format!("{who} named it {new}"),
                (Some(old), None) => format!("{who} removed the name {old}"),
                (None, None) => format!("{who}: {label}"),
            }
        }
        Key::Comment(address) => match after {
            Some(_) => format!("{who} commented at {address:X}"),
            None => format!("{who} removed a comment at {address:X}"),
        },
        Key::Bookmark(_, address) => format!("{who} bookmarked {address:X}"),
        Key::Number(..)
        | Key::Type(_)
        | Key::Definition(_)
        | Key::Item(_)
        | Key::Bounds(_)
        | Key::DebugFile
        | Key::Thread(_)
        | Key::Post(_)
        | Key::Suggestion(_)
        | Key::Signature(_) => format!("{who}: {label}"),
    }
}

/// One line of the chat panel: a message, or a line of the session's own
/// (someone joined or left).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChatItem {
    /// A message.
    Message(ChatLine),
    /// The session's line: its text, when (Unix milliseconds).
    System {
        /// What it says.
        text: String,
        /// When.
        time: u64,
    },
}

/// Messages one after another by one author: under one header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChatGroup {
    /// An author's messages: the first one's author and time, then each
    /// text.
    Messages {
        /// Their author.
        from: PublicKey,
        /// The author's name.
        name: String,
        /// The first one's time.
        time: u64,
        /// The texts, in order.
        texts: Vec<ChatText>,
    },
    /// A line of the session's: its text, when (Unix milliseconds).
    System(String, u64),
}

/// One message under its author's header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatText {
    /// Its id.
    pub id: u64,
    /// What it says (empty once removed).
    pub text: String,
    /// Whether the owner removed it.
    pub removed: bool,
    /// The places its text names.
    pub links: Vec<ChatLink>,
    /// Whom it @mentions.
    pub mentions: Vec<PublicKey>,
}

impl ChatText {
    /// What it shows: its text, or that the owner removed it.
    pub fn shown(&self) -> &str {
        if self.removed {
            "removed by the owner"
        } else {
            &self.text
        }
    }
}

/// The owner removed chat message `id`: its line in `items` blanked to
/// "removed by the owner" where it is. Whether it was there (one still to
/// come is blanked as it comes: [`ChatLine::removed`]).
pub fn remove_chat<'a>(items: impl IntoIterator<Item = &'a mut ChatItem>, id: u64) -> bool {
    let mut found = false;
    for item in items {
        if let ChatItem::Message(line) = item
            && line.id == id
        {
            line.text.clear();
            line.links.clear();
            line.mentions.clear();
            line.removed = true;
            found = true;
        }
    }
    found
}

/// How long apart two messages of one author may be and share a header.
const GROUPED_MS: u64 = 5 * 60 * 1000;

/// `items` grouped for showing: consecutive messages of one author (5
/// minutes apart at most) under one header; the session's lines alone.
pub fn group_chat<'a>(items: impl IntoIterator<Item = &'a ChatItem>) -> Vec<ChatGroup> {
    let mut groups: Vec<ChatGroup> = Vec::new();
    let mut last_time = 0;
    for item in items {
        match item {
            ChatItem::System { text, time } => groups.push(ChatGroup::System(text.clone(), *time)),
            ChatItem::Message(line) => {
                let joins = matches!(
                    groups.last(),
                    Some(ChatGroup::Messages { from, .. }) if *from == line.from
                ) && line.time.saturating_sub(last_time) <= GROUPED_MS;
                if joins && let Some(ChatGroup::Messages { texts, .. }) = groups.last_mut() {
                    texts.push(chat_text(line));
                } else {
                    groups.push(ChatGroup::Messages {
                        from: line.from,
                        name: line.name.clone(),
                        time: line.time,
                        texts: vec![chat_text(line)],
                    });
                }
                last_time = line.time;
            }
        }
    }
    groups
}

/// `line`'s text under its header.
fn chat_text(line: &ChatLine) -> ChatText {
    ChatText {
        id: line.id,
        text: line.text.clone(),
        removed: line.removed,
        links: line.links.clone(),
        mentions: line.mentions.clone(),
    }
}

/// `ms` (Unix milliseconds) in `zone`.
fn zoned(ms: u64, zone: &TimeZone) -> Option<Zoned> {
    let ms = i64::try_from(ms).ok()?;
    Some(Timestamp::from_millisecond(ms).ok()?.to_zoned(zone.clone()))
}

/// When a chat message was sent (`ms`: Unix milliseconds, as on the wire
/// and in memory), as the chat shows it in the user's time zone `zone`:
/// `16:55` (24-hour) today (`now_ms`), with the date on another day:
/// `Nov 12 16:55`, and the year in another year.
pub fn local_clock(ms: u64, now_ms: u64, zone: &TimeZone) -> String {
    let (Some(then), Some(now)) = (zoned(ms, zone), zoned(now_ms, zone)) else {
        return String::new();
    };
    let format = if then.date() == now.date() {
        "%H:%M"
    } else if then.year() == now.year() {
        "%b %-d %H:%M"
    } else {
        "%b %-d %Y %H:%M"
    };
    then.strftime(format).to_string()
}

/// The whole date, time and zone of `ms` in `zone`, for the tooltip:
/// `2026-11-13 16:55:02 EST`.
pub fn local_full(ms: u64, zone: &TimeZone) -> String {
    zoned(ms, zone).map_or_else(String::new, |then| {
        then.strftime("%Y-%m-%d %H:%M:%S %Z").to_string()
    })
}

/// Whom this window follows, and where it last went for them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Follow {
    leader: Option<PublicKey>,
    landed: Option<Cursor>,
}

impl Follow {
    /// Whom it follows.
    pub fn leader(&self) -> Option<PublicKey> {
        self.leader
    }

    /// Follows `leader` from now: where to go now, their cursor if known.
    pub fn start(&mut self, leader: PublicKey, cursor: Option<Cursor>) -> Option<Cursor> {
        self.leader = Some(leader);
        self.landed = None;
        self.moved(leader, cursor?)
    }

    /// Stops following; whom it followed.
    pub fn stop(&mut self) -> Option<PublicKey> {
        self.landed = None;
        self.leader.take()
    }

    /// `who`'s cursor moved to `cursor`: where to go, if this window
    /// follows them and it is somewhere else than where it went last.
    pub fn moved(&mut self, who: PublicKey, cursor: Cursor) -> Option<Cursor> {
        if self.leader != Some(who) || self.landed == Some(cursor) {
            return None;
        }
        self.landed = Some(cursor);
        Some(cursor)
    }
}

/// What `key` is about, and its address if it has one.
pub fn key_text(key: &Key) -> (String, Option<u64>) {
    match key {
        Key::FunctionName(a) => (format!("Function name at {a:X}"), Some(*a)),
        Key::GlobalName(a) => (format!("Global name at {a:X}"), Some(*a)),
        Key::VariableName(v) => (
            format!("Variable of the function at {:X}", v.function),
            Some(v.function),
        ),
        Key::Slot(entry, offset) => (
            format!("Frame slot {offset:+#x} of the function at {entry:X}"),
            Some(*entry),
        ),
        Key::Comment(a) => (format!("Comment at {a:X}"), Some(*a)),
        Key::Bookmark(_, a) => (format!("Bookmark at {a:X}"), Some(*a)),
        Key::Number(a, v) => (format!("Form of {v:#x} at {a:X}"), Some(*a)),
        Key::Type(typed) => (format!("Type of {typed:?}"), None),
        Key::Definition(name) => (format!("Definition of {name}"), None),
        Key::Item(a) => (format!("Correction at {a:X}"), Some(*a)),
        Key::Bounds(a) => (format!("Bounds of the function at {a:X}"), Some(*a)),
        Key::DebugFile => ("Debug file".to_owned(), None),
        Key::Thread(_) => ("Thread".to_owned(), None),
        Key::Post(_) => ("Post".to_owned(), None),
        Key::Suggestion(_) => ("Suggestion".to_owned(), None),
        Key::Signature(a) => (format!("Signature match at {a:X}"), Some(*a)),
    }
}

/// A value as a conflict card shows it.
pub fn value_text(value: &Value) -> String {
    match value {
        Value::Text(Some(text)) => format!("`{text}`"),
        Value::Text(None)
        | Value::Number(None)
        | Value::Item(None)
        | Value::Bounds(None)
        | Value::DebugFile(None)
        | Value::Signature(None) => "nothing (removed)".to_owned(),
        Value::Number(Some(stated)) => format!("{:#x} as {}", stated.value, stated.form.name()),
        Value::Item(Some(item)) => format!("{item:?}"),
        Value::Bounds(Some(bounds)) => format!("{bounds:?}"),
        Value::DebugFile(Some(debug)) => format!("{debug:?}"),
        Value::Signature(Some(identified)) => format!(
            "{} ({} {}, {}){}",
            identified.name,
            identified.library,
            identified.version,
            identified.how,
            if identified.rejected {
                ", rejected"
            } else {
                ""
            }
        ),
        Value::Thread(_) | Value::Post(_) | Value::Suggestion(_) => "conversation".to_owned(),
    }
}

/// A conflict's card: what it is about, each value by whom (the one
/// shown marked), as `name` names authors. "Ann named it `aes_init` and
/// Bob named it `key_setup` at the same time: `key_setup` shows."
pub fn conflict_text(conflict: &Conflict, name: &dyn Fn(PublicKey) -> String) -> String {
    let (what, _) = key_text(&conflict.key);
    let values: Vec<String> = conflict
        .leaves
        .iter()
        .map(|leaf| format!("{} chose {}", name(leaf.author), value_text(&leaf.value)))
        .collect();
    let shown = conflict
        .leaves
        .iter()
        .find(|leaf| leaf.op == conflict.shown)
        .map(|leaf| value_text(&leaf.value))
        .unwrap_or_default();
    format!(
        "{what}: {} at the same time; {shown} shows (the later).",
        values.join(" and ")
    )
}

/// The banner saying this analysis differs from a participant's, if one
/// does: a debug file another than theirs (or none where they have one),
/// else another analysis fingerprint. Where they analyse with a
/// debug file this one lacks and this peer is linked to them (`linked`),
/// it offers to get it from them; while it comes (`fetching`), it says how
/// far it is.
pub fn analysis_banner(
    mine: Option<&Analysis>,
    people: &[Person],
    linked: &[PublicKey],
    fetching: Option<&Fetching>,
) -> Option<Banner> {
    if let Some(fetching) = fetching.filter(|fetching| fetching.debug) {
        let from = people
            .iter()
            .find(|person| person.key == fetching.from)
            .map_or_else(|| fingerprint(fetching.from), |person| person.name.clone());
        return Some(Banner {
            kind: Kind::Analysis,
            priority: Priority::Session,
            about: String::new(),
            text: fetch_text(fetching, &from),
            tone: Tone::Busy,
            buttons: Vec::new(),
            closable: false,
        });
    }
    let mine = mine?;
    let (person, theirs) = people
        .iter()
        .filter_map(|person| Some((person, person.analysis.as_ref()?)))
        .find(|(_, theirs)| theirs.fingerprint != mine.fingerprint)?;
    let text = if theirs.debug.as_ref().map(|d| d.1) == mine.debug.as_ref().map(|d| d.1) {
        format!(
            "Your analysis differs from {}'s (another fingerprint): edits may resolve differently",
            person.name
        )
    } else {
        match (&theirs.debug, &mine.debug) {
            (Some((file, _)), _) => format!(
                "Your debug files differ from {}'s: they analyse with {file}",
                person.name
            ),
            (None, Some((file, _))) => format!(
                "Your debug files differ from {}'s: you analyse with {file}, they without",
                person.name
            ),
            (None, None) => String::new(),
        }
    };
    let fetchable = theirs.debug.is_some()
        && theirs.debug.as_ref().map(|d| d.1) != mine.debug.as_ref().map(|d| d.1)
        && linked.contains(&person.key);
    let buttons = if fetchable {
        vec![Button {
            label: format!("Get it from {}", person.name),
            action: Action::FetchDebug(person.key),
        }]
    } else {
        Vec::new()
    };
    Some(Banner {
        kind: Kind::Analysis,
        priority: Priority::Session,
        about: format!("{}:{}", person.name, text),
        text,
        tone: Tone::Info,
        buttons,
        closable: true,
    })
}

/// A file a peer offers that this window lacks, as the Join dialog shows
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offered {
    /// Its file name.
    pub name: String,
    /// Its bytes.
    pub length: u64,
    /// Its SHA-256.
    pub sha256: [u8; 32],
    /// Who offers it.
    pub from: PublicKey,
    /// The slice shared, of a universal Mach-O file.
    pub arch: Option<String>,
}

/// A fetch under way, as the window shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetching {
    /// The file's name.
    pub name: String,
    /// From whom.
    pub from: PublicKey,
    /// Whether it is a debug file (else the binary).
    pub debug: bool,
    /// Whether it is being opened (decrypted), else fetched.
    pub opening: bool,
    /// The bytes done.
    pub done: u64,
    /// Of these.
    pub total: u64,
}

impl Fetching {
    /// How far it is, from 0 to 1.
    pub fn fraction(&self) -> f32 {
        let permille = self
            .done
            .saturating_mul(1000)
            .checked_div(self.total)
            .unwrap_or(0);
        f32::from(u16::try_from(permille.min(1000)).unwrap_or(1000)) / 1000.0
    }
}

/// `bytes` for people: kilobytes under a megabyte, else megabytes.
pub fn size_text(bytes: u64) -> String {
    let tenths = |unit: u64| {
        let tenths = bytes / (unit / 10);
        format!("{}.{}", tenths / 10, tenths % 10)
    };
    if bytes < 1_000_000 {
        format!("{} kB", tenths(1000))
    } else {
        format!("{} MB", tenths(1_000_000))
    }
}

/// What a fetch under way says: what, from whom (`from`), how far.
pub fn fetch_text(fetching: &Fetching, from: &str) -> String {
    let percent = fetching
        .done
        .saturating_mul(100)
        .checked_div(fetching.total)
        .unwrap_or(0);
    if fetching.opening {
        format!(
            "Opening {}: {} of {} ({percent} %)",
            fetching.name,
            size_text(fetching.done),
            size_text(fetching.total)
        )
    } else {
        format!(
            "Getting {} from {from}: {} of {} ({percent} %)",
            fetching.name,
            size_text(fetching.done),
            size_text(fetching.total)
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn an_answer_to_a_card_gone_answers_no_other() {
        let mut approvals = Approvals::default();
        approvals.push(1, "Ann");
        approvals.push(2, "Bob");
        // Both cards show, Ann's first; her buttons are drawn with her id.
        let shown: Vec<_> = approvals.iter().collect();
        assert_eq!(shown, [(1, &"Ann"), (2, &"Bob")]);
        // Ann withdraws before the click lands: Bob's card is left.
        assert_eq!(approvals.take(1), Some("Ann"));
        assert!(approvals.iter().eq([(2, &"Bob")]));
        // The click drawn for Ann answers nothing, and Bob still waits.
        assert_eq!(approvals.take(1), None);
        assert!(approvals.iter().eq([(2, &"Bob")]));
        // A click on Bob's card answers Bob, wherever he is in the queue.
        approvals.push(3, "Cat");
        assert_eq!(approvals.take(3), Some("Cat"));
        assert_eq!(approvals.take(2), Some("Bob"));
        assert!(approvals.is_empty());
    }

    #[test]
    fn the_members_row_lists_those_not_removed_in_the_order_admitted() {
        let (ann, dan, bob, carol) = (
            PublicKey([1; 32]),
            PublicKey([2; 32]),
            PublicKey([3; 32]),
            PublicKey([4; 32]),
        );
        let admitted = [
            (ann, Some(Role::Owner)),
            (dan, Some(Role::Editor)),
            (bob, None),
            (carol, Some(Role::Viewer)),
        ];
        assert_eq!(
            listed_members(&admitted),
            [
                (ann, Role::Owner),
                (dan, Role::Editor),
                (carol, Role::Viewer)
            ]
        );
    }

    #[test]
    fn a_card_pasted_is_taken_whole_and_other_texts_say_what_they_are() {
        // A paste wrapped over lines, upper case, padded: the card whole.
        assert_eq!(
            card_text("  BINBUNIDAB\n CD\t\n").as_deref(),
            Ok("BINBUNIDABCD")
        );
        // Every kind starts with `binbun`: each told apart from a card.
        for (text, what) in [
            (" \n", NotCard::Empty),
            ("binbunabc", NotCard::Ticket),
            ("bin-bunid", NotCard::Other),
        ] {
            assert_eq!(card_text(text), Err(what), "{text:?}");
        }
    }

    #[test]
    fn ones_own_card_and_a_members_are_refused_one_removed_is_not() {
        let (ann, bob, carol) = (PublicKey([1; 32]), PublicKey([3; 32]), PublicKey([4; 32]));
        let members = listed_members(&[
            (ann, Some(Role::Owner)),
            (bob, Some(Role::Editor)),
            (carol, None),
        ]);
        assert_eq!(card_refused(ann, ann, &members), Some(CardRefused::Own));
        assert_eq!(card_refused(bob, ann, &members), Some(CardRefused::Member));
        assert_eq!(card_refused(carol, ann, &members), None);
        assert_eq!(card_refused(PublicKey([9; 32]), ann, &members), None);
    }

    #[test]
    fn white_ink_reads_on_every_avatar_and_every_avatar_stands_out() {
        // APCA lightness contrast (APCA-W3 0.0.98G) of text on a
        // background, as |Lc|: about 106 for black on white.
        let apca = |text: u32, background: u32| {
            let screen = |rgb: u32| {
                let channel = |shift: u32| {
                    (f32::from(u8::try_from((rgb >> shift) & 0xff).unwrap()) / 255.0).powf(2.4)
                };
                let y =
                    0.212_672_9 * channel(16) + 0.715_152_2 * channel(8) + 0.072_175 * channel(0);
                if y > 0.022 {
                    y
                } else {
                    y + (0.022 - y).powf(1.414)
                }
            };
            let (t, b) = (screen(text), screen(background));
            let s = if b > t {
                (b.powf(0.56) - t.powf(0.57)) * 1.14
            } else {
                (b.powf(0.65) - t.powf(0.62)) * 1.14
            };
            if s.abs() < 0.1 {
                0.0
            } else {
                (s.abs() - 0.027) * 100.0
            }
        };
        assert!((apca(0, 0x00ff_ffff) - 106.0).abs() < 0.5);
        // Every colour of both palettes keeps white initials at Lc 55
        // (above the method's floor of 45 for large, heavy text and
        // icons) and stands out on its theme's background as a caret
        // (WCAG 3:1).
        let contrast = |a: f32, b: f32| (a.max(b) + 0.05) / (a.min(b) + 0.05);
        for dark in [false, true] {
            let background = luminance(if dark { 0x001e_1e1e } else { 0x00ff_ffff });
            for slot in 0..PALETTE {
                let circle = avatar_rgb(slot, dark);
                let at = format!("slot {slot}, dark {dark}");
                assert!(apca(AVATAR_INK, circle) >= 55.0, "{at}: unreadable");
                assert!(
                    contrast(luminance(circle), background) >= 3.0,
                    "{at}: faint"
                );
            }
        }
        // A slot past the palette wraps.
        assert_eq!(avatar_rgb(PALETTE + 2, true), avatar_rgb(2, true));
    }

    #[test]
    fn the_status_says_the_path_in_use_never_an_address_and_who_a_stop_drops() {
        let people = |list: &[&str]| list.iter().map(|&n| n.to_owned()).collect::<Vec<_>>();
        assert_eq!(stop_text(&[]), None);
        assert_eq!(
            stop_text(&people(&["Bob"])).as_deref(),
            Some("Stop sharing? Bob will be disconnected.")
        );
        assert_eq!(
            stop_text(&people(&["Bob", "Cy", "Di"])).as_deref(),
            Some("Stop sharing? Bob, Cy and Di will be disconnected.")
        );
        assert_eq!(
            link_text("*direct 192.168.122.1:40788 (0.5 ms)"),
            "direct 0.5 ms"
        );
        assert_eq!(
            link_text(
                "direct 10.0.0.2:1 (9.0 ms), *relay https://euw1-1.relay.iroh.network./ (31.2 ms)"
            ),
            "relay 31.2 ms"
        );
        assert_eq!(
            link_text("*direct 100.67.1.2:9 (tailnet) (2.1 ms)"),
            "tailnet 2.1 ms"
        );
        // Another window on this machine, reached at its tailnet address.
        assert_eq!(
            link_text("*direct 100.67.192.16:52196 (loopback) (1.3 ms)"),
            "loopback 1.3 ms"
        );
        assert_eq!(link_text("no path"), "connecting");
        let named = |key: &Key| match key {
            Key::VariableName(_) => Some("v15".to_owned()),
            Key::FunctionName(_)
            | Key::GlobalName(_)
            | Key::Slot(..)
            | Key::Comment(_)
            | Key::Bookmark(..)
            | Key::Number(..)
            | Key::Type(_)
            | Key::Definition(_)
            | Key::Item(_)
            | Key::Bounds(_)
            | Key::DebugFile
            | Key::Thread(_)
            | Key::Post(_)
            | Key::Suggestion(_)
            | Key::Signature(_) => None,
        };
        let var = Key::VariableName(binbun_session::Variable {
            function: 0x1e680,
            origins: Vec::new(),
            ordinal: 0,
        });
        let text = |s: &str| Value::Text(Some(s.to_owned()));
        assert_eq!(
            change_text(
                "Bob",
                "Rename variable",
                &[(var.clone(), text("fd"), Value::Text(None))],
                &named
            ),
            "Bob renamed v15 → fd"
        );
        // A name of the user's before wins over the engine's.
        assert_eq!(
            change_text(
                "Bob",
                "Rename variable",
                &[(var, text("fd"), text("len"))],
                &named
            ),
            "Bob renamed len → fd"
        );
        assert_eq!(
            change_text(
                "Bob",
                "Rename function",
                &[(Key::FunctionName(1), text("f"), Value::Text(None))],
                &named
            ),
            "Bob named it f"
        );
        // A change of several edits: its label.
        assert_eq!(
            change_text("Bob", "Name crypto helpers", &[], &named),
            "Bob: Name crypto helpers"
        );
        // What a peer wrote is escaped field by field: no line break, no
        // reordering, nothing hidden.
        let said = change_text(
            "Bob\u{202e}",
            "Rename function",
            &[(
                Key::FunctionName(1),
                text("f\nAnn renamed g"),
                Value::Text(None),
            )],
            &named,
        );
        assert_eq!(said, "Bob\\u{202e} named it f\\u{a}Ann renamed g");
        assert_eq!(
            change_text("Bob", "x\u{1b}[2J", &[], &named),
            "Bob: x\\u{1b}[2J"
        );
    }

    #[test]
    fn chat_times_show_in_the_users_zone_with_the_date_on_other_days() {
        // A zone of the test's own (US Eastern by its POSIX rule), never
        // the machine's.
        let zone = TimeZone::posix("EST5EDT,M3.2.0,M11.1.0").unwrap();
        let ms =
            |at: &str| u64::try_from(at.parse::<Timestamp>().unwrap().as_millisecond()).unwrap();
        let now = ms("2026-11-13T23:00:00Z");
        let sent = ms("2026-11-13T21:55:02Z");
        assert_eq!(local_clock(sent, now, &zone), "16:55");
        assert_eq!(local_full(sent, &zone), "2026-11-13 16:55:02 EST");
        // The day before there (UTC's same day): the date too.
        assert_eq!(
            local_clock(ms("2026-11-13T03:10:00Z"), now, &zone),
            "Nov 12 22:10"
        );
        // In summer time, its own abbreviation.
        assert_eq!(
            local_full(ms("2026-07-01T12:00:00Z"), &zone),
            "2026-07-01 08:00:00 EDT"
        );
        assert_eq!(
            local_clock(ms("2025-12-31T23:30:00Z"), now, &zone),
            "Dec 31 2025 18:30"
        );
    }

    #[test]
    fn chat_groups_an_authors_run_and_breaks_at_others_and_the_sessions_lines() {
        let line = |from: u8, time: u64, text: &str| {
            ChatItem::Message(ChatLine {
                id: time,
                from: key(from),
                name: format!("p{from}"),
                time,
                text: text.to_owned(),
                removed: false,
                links: Vec::new(),
                mentions: Vec::new(),
            })
        };
        let mut items = [
            line(1, 0, "a"),
            line(1, 1000, "b"),
            line(2, 2000, "c"),
            ChatItem::System {
                text: "p3 joined".to_owned(),
                time: 2500,
            },
            line(2, 3000, "d"),
            // Six minutes later: a header again.
            line(2, 363_000, "e"),
        ];
        let messages = |from: u8, time: u64, texts: &[(u64, &str)]| ChatGroup::Messages {
            from: key(from),
            name: format!("p{from}"),
            time,
            texts: texts
                .iter()
                .map(|&(id, t)| ChatText {
                    id,
                    text: t.to_owned(),
                    removed: false,
                    links: Vec::new(),
                    mentions: Vec::new(),
                })
                .collect(),
        };
        assert_eq!(
            group_chat(&items),
            [
                messages(1, 0, &[(0, "a"), (1000, "b")]),
                messages(2, 2000, &[(2000, "c")]),
                ChatGroup::System("p3 joined".to_owned(), 2500),
                messages(2, 3000, &[(3000, "d")]),
                messages(2, 363_000, &[(363_000, "e")]),
            ]
        );
        // The owner removes "b": blanked where it was, the group kept, its
        // line saying so; an id not there changes nothing.
        assert!(remove_chat(items.iter_mut(), 1000));
        assert!(!remove_chat(items.iter_mut(), 42));
        let groups = group_chat(&items);
        let Some(ChatGroup::Messages { texts, .. }) = groups.first() else {
            panic!("no first group");
        };
        let shown: Vec<(&str, bool)> = texts.iter().map(|t| (t.shown(), t.removed)).collect();
        assert_eq!(shown, [("a", false), ("removed by the owner", true)]);
        assert!(texts.get(1).is_some_and(|t| t.text.is_empty()));
    }

    fn key(n: u8) -> PublicKey {
        PublicKey([n; 32])
    }

    #[test]
    fn a_location_names_the_function_the_address_and_the_view() {
        let at = |place| Cursor {
            place,
            address: 0x1E720,
            column: 4,
            selection: None,
        };
        let c = Place::C {
            function: 0x1E680,
            reading: true,
            line: 9,
        };
        let here = Whereabouts::of(&at(c), Some("push_stream".to_owned()));
        assert_eq!(here.address, "1E720");
        assert_eq!(here.text(), "push_stream \u{b7} 1E720 \u{b7} C");
        assert_eq!(
            Whereabouts::of(&at(Place::Hex), None).text(),
            "1E720 \u{b7} hex"
        );
        let views: Vec<&str> = [
            Place::Listing,
            Place::Graph { function: 0x1E680 },
            Place::Xrefs,
        ]
        .into_iter()
        .map(|place| Whereabouts::of(&at(place), None).view)
        .collect();
        assert_eq!(views, ["listing", "graph", "xrefs"]);
    }

    #[test]
    fn ticks_at_nearly_one_spot_stay_apart_and_inside_the_strip() {
        // Apart already: where they are.
        assert_eq!(spread_ticks(&[10.0, 50.0], 5.0, 100.0), [10.0, 50.0]);
        // Three at about one spot, given in any order: each 5 below the
        // one above, the topmost where it was.
        assert_eq!(
            spread_ticks(&[21.0, 20.0, 20.5], 5.0, 100.0),
            [30.0, 20.0, 25.0]
        );
        // At the very end: backed up so the last fits.
        assert_eq!(
            spread_ticks(&[98.0, 97.0, 10.0], 5.0, 100.0),
            [95.0, 90.0, 10.0]
        );
        // More than the strip holds: the last at its end, the rest from
        // its start, never above it.
        assert_eq!(spread_ticks(&[0.0, 0.0, 0.0], 5.0, 8.0), [0.0, 0.0, 3.0]);
    }

    #[test]
    fn the_stack_shows_four_or_three_and_a_chip_with_the_followed_one_kept() {
        let order: Vec<PublicKey> = (1..=8).map(key).collect();
        let three = order.get(..3).unwrap_or_default();
        assert_eq!(stack(three, None), (three.to_vec(), 0));
        let four = order.get(..4).unwrap_or_default();
        assert_eq!(stack(four, Some(key(1))), (four.to_vec(), 0));
        let five = order.get(..5).unwrap_or_default();
        assert_eq!(stack(five, None), (vec![key(3), key(4), key(5)], 2));
        // Following the first who came: kept, in front.
        assert_eq!(
            stack(&order, Some(key(1))),
            (vec![key(1), key(7), key(8)], 5)
        );
        assert_eq!(
            stack(&order, Some(key(8))),
            (vec![key(6), key(7), key(8)], 5)
        );
    }

    #[test]
    fn an_impostor_is_flagged_red_and_never_admitted_unasked() {
        let dir = std::env::temp_dir().join(format!("binbun-known-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = Known::path_in(&dir, "0011");
        let mut known = Known::load(path.clone());
        known.admit(key(1), "Ann Smith", 100);
        known.save().unwrap();
        // Kept: read again, the same.
        let known = Known::load(path);
        assert_eq!(known.people()[&key(1)].names, ["Ann Smith"]);

        // Ann again: known, admitted unasked only when the host says so.
        let ann = known.judge(key(1), "Ann Smith", &[]);
        assert_eq!(ann, Trust::Known { was: None });
        assert!(admits_unasked(&ann, true) && !admits_unasked(&ann, false));
        // Ann under a new name: known, but asked.
        let renamed = known.judge(key(1), "Annie", &[]);
        assert_eq!(
            renamed,
            Trust::Known {
                was: Some("Ann Smith".to_owned())
            }
        );
        assert!(!admits_unasked(&renamed, true));
        // A new key calling itself Ann, in another case, with a Cyrillic
        // а and a zero-width space: an impostor, never admitted unasked.
        for name in [
            "Ann Smith",
            "ann smith",
            "\u{430}nn Sm\u{200b}ith",
            "Ann 5mith",
        ] {
            let trust = known.judge(key(2), name, &[]);
            if name == "Ann 5mith" {
                // `5` is not taken for `s`: a name merely near another's.
                assert_eq!(trust, Trust::New);
                continue;
            }
            assert_eq!(
                trust,
                Trust::Impostor {
                    like: "Ann Smith".to_owned()
                },
                "{name}"
            );
            assert!(!admits_unasked(&trust, true));
            let (text, red) = trust_text(&trust, name);
            assert!(red && text.contains("Not the Ann Smith you know"));
        }
        // Like a participant (or the host), not only those kept.
        assert_eq!(
            known.judge(key(3), "Bob", &[(key(4), "B0b".to_owned())]),
            Trust::Impostor {
                like: "B0b".to_owned()
            }
        );
        assert_eq!(known.judge(key(3), "Bob", &[]), Trust::New);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn skeletons_make_look_alikes_one() {
        assert_eq!(skeleton("Rnary"), skeleton("mary"));
        assert_eq!(skeleton("WiII"), skeleton("will"));
        assert_ne!(skeleton("Ann"), skeleton("Anna"));
    }

    #[test]
    fn characters_that_show_nothing_neither_hide_an_impostor_nor_reach_the_screen_raw() {
        let mut known = Known::load(std::env::temp_dir().join(format!(
            "binbun-known-invisible-{}/known.toml",
            std::process::id()
        )));
        known.admit(key(1), "Ann Smith", 100);
        // Bidirectional controls, an isolate, a tag letter, a soft hyphen,
        // a variation selector, a bell: each shows nothing, so the name
        // looks like Ann's.
        for name in [
            "Ann\u{202e} Smith",
            "A\u{2066}nn Smi\u{e0041}th",
            "Ann Sm\u{ad}ith",
            "Ann\u{fe0f} Smith",
            "Ann Smith\u{7}",
        ] {
            assert_eq!(
                known.judge(key(2), name, &[]),
                Trust::Impostor {
                    like: "Ann Smith".to_owned()
                },
                "{name:?}"
            );
        }
        // Dropped before the look-alike pairs: `r`, a zero-width joiner,
        // `n` is `m`.
        assert_eq!(skeleton("r\u{200d}nary"), skeleton("mary"));
        // Shown, each is its code point, the rest as it is.
        assert_eq!(
            shown_name("Ann\u{202e}\u{1b}[2Jé"),
            "Ann\\u{202e}\\u{1b}[2Jé"
        );
        let (text, red) = trust_text(
            &Trust::Impostor {
                like: "Bob\u{2067}".to_owned(),
            },
            "B0b",
        );
        assert!(red && text.contains("Bob\\u{2067}") && !text.contains('\u{2067}'));
    }

    #[test]
    fn following_goes_where_the_leader_goes_once_each_until_stopped() {
        let here = |address| Cursor {
            place: Place::Listing,
            address,
            column: 0,
            selection: None,
        };
        let mut follow = Follow::default();
        assert_eq!(follow.moved(key(1), here(5)), None);
        assert_eq!(follow.start(key(1), Some(here(5))), Some(here(5)));
        // The same place again (a heartbeat): nowhere to go.
        assert_eq!(follow.moved(key(1), here(5)), None);
        // Someone else's cursor: not followed.
        assert_eq!(follow.moved(key(2), here(6)), None);
        assert_eq!(follow.moved(key(1), here(6)), Some(here(6)));
        assert_eq!(follow.stop(), Some(key(1)));
        assert_eq!(follow.moved(key(1), here(7)), None);
    }

    #[test]
    fn initials_capitals_are_whole_pixels_leaving_equal_margins_in_the_circle() {
        // Plex Sans (0.698), Inter (0.727), a squat face (0.66); circles
        // at every whole size and at 1.25× and 1.5× scales.
        for cap_per_size in [0.698, 0.727, 0.66] {
            for whole in 12_u16..=72 {
                for scale in [1.0, 1.25, 1.5] {
                    let diameter = f32::from(whole) * scale;
                    let (size, cap) = initials_size(diameter, cap_per_size, 1);
                    let margin = (diameter.round() - cap) / 2.0;
                    assert_eq!(cap.fract(), 0.0, "{diameter} {cap_per_size}");
                    assert_eq!(margin.fract(), 0.0, "{diameter} {cap_per_size}");
                    assert!((size * cap_per_size - cap).abs() < 1e-3);
                    // About half the circle: off 0.525 by at most a pixel
                    // of capitals either way.
                    let off = (size - 0.525 * diameter).abs();
                    assert!(off <= 1.0 / cap_per_size + 1e-3, "{diameter} {size}");
                    let (two, _) = initials_size(diameter, cap_per_size, 2);
                    assert!(two <= size, "{diameter}: two letters are no larger");
                }
            }
        }
        // A tiny circle still gets capitals, of its parity.
        assert_eq!(initials_size(2.0, 0.7, 1).1, 2.0);
        assert_eq!(initials_size(3.0, 0.7, 1).1, 1.0);
    }

    #[test]
    fn avatars_are_the_initials_on_a_colour_of_the_key() {
        let colours = Colours::default();
        let a = colours.avatar(key(1), "ann smith");
        assert_eq!(a.initials, "AS");
        assert_eq!(a.slot, preferred(key(1)));
        assert_eq!(colours.avatar(key(1), " ").initials, "?");
    }

    /// The first `n` keys (in key order) whose hashes ask for `slot`.
    fn asking(slot: usize, n: usize) -> Vec<PublicKey> {
        (0..=u8::MAX)
            .flat_map(|a| (0..=u8::MAX).map(move |b| (a, b)))
            .map(|(a, b)| {
                let mut bytes = [0; 32];
                bytes[..2].copy_from_slice(&[a, b]);
                PublicKey(bytes)
            })
            .filter(|&k| preferred(k) == slot)
            .take(n)
            .collect()
    }

    /// Whether every two of `keys` have slots [`SEPARATION`] or more apart.
    fn well_apart(colours: &Colours, keys: &[PublicKey]) -> bool {
        let slots: Vec<usize> = keys.iter().map(|&k| colours.slot(k)).collect();
        slots.iter().enumerate().all(|(i, &a)| {
            slots
                .get(i + 1..)
                .unwrap_or_default()
                .iter()
                .all(|&b| apart(a, b) >= SEPARATION)
        })
    }

    #[test]
    fn members_whose_hashes_clash_are_given_hues_well_apart() {
        // Red, orange and pink: neighbours around the palette.
        let three = [asking(0, 1)[0], asking(1, 1)[0], asking(PALETTE - 1, 1)[0]];
        assert!(well_apart(&Colours::of(&three), &three));
        // Five asking for one slot are spread around the palette; the
        // first by key keeps it.
        let five = asking(4, 5);
        let colours = Colours::of(&five);
        assert!(well_apart(&colours, &five));
        assert_eq!(colours.slot(five[0]), 4);
        // Past what the palette spreads, each still has their own slot;
        // past the palette, the slot given first is given again.
        let keys = asking(4, PALETTE + 2);
        let all = Colours::of(&keys);
        let distinct: BTreeSet<usize> = keys[..PALETTE].iter().map(|&k| all.slot(k)).collect();
        assert_eq!(distinct.len(), PALETTE);
        assert_eq!(all.slot(keys[PALETTE]), all.slot(keys[0]));
        assert_eq!(all.slot(keys[PALETTE + 1]), all.slot(keys[1]));
    }

    #[test]
    fn the_same_members_in_any_order_have_the_same_colours() {
        let mut keys = asking(2, 3);
        keys.extend(asking(3, 2));
        keys.extend(asking(7, 1));
        keys.push(key(1));
        let colours = Colours::of(&keys);
        let mut reversed = keys.clone();
        reversed.reverse();
        assert_eq!(Colours::of(&reversed), colours);
        for turn in 1..keys.len() {
            let mut turned = keys.clone();
            turned.rotate_left(turn);
            assert_eq!(Colours::of(&turned), colours, "{turn}");
        }
        // A member listed twice (readmitted) counts once.
        let mut again = keys.clone();
        again.push(keys[0]);
        again.insert(0, keys[4]);
        assert_eq!(Colours::of(&again), colours);
    }

    #[test]
    fn a_member_whose_hash_clashes_with_no_one_keeps_its_hue() {
        // 0 and 5 are far from each other and from 7 and 8; the two
        // asking for 7 and the one for 8 clash among themselves.
        let lone = [asking(0, 1)[0], asking(5, 1)[0]];
        let mut keys = lone.to_vec();
        keys.extend(asking(7, 2));
        keys.extend(asking(8, 1));
        let colours = Colours::of(&keys);
        assert_eq!(colours.slot(lone[0]), 0);
        assert_eq!(colours.slot(lone[1]), 5);
        // Whoever else joins without a clash, they keep it.
        assert_eq!(Colours::of(&lone).slot(lone[0]), 0);
        let distinct: BTreeSet<usize> = keys.iter().map(|&k| colours.slot(k)).collect();
        assert_eq!(distinct.len(), keys.len());
    }

    #[test]
    fn the_banner_names_the_peer_whose_debug_file_or_analysis_differs() {
        let mine = Analysis {
            fingerprint: [1; 32],
            debug: None,
        };
        let person = |fingerprint, debug: Option<(String, [u8; 32])>| Person {
            key: key(2),
            name: "Ann".to_owned(),
            engine: EngineVersion::this(),
            analysis: Some(Analysis { fingerprint, debug }),
            cursor: None,
            following: None,
            role: None,
            path: None,
            view_only: None,
            agent: None,
        };
        let same = [person([1; 32], None)];
        assert_eq!(analysis_banner(Some(&mine), &same, &[], None), None);
        let theirs = [person([2; 32], Some(("libfoo.debug".to_owned(), [3; 32])))];
        let debug = analysis_banner(Some(&mine), &theirs, &[], None).unwrap();
        assert_eq!(
            debug.text,
            "Your debug files differ from Ann's: they analyse with libfoo.debug"
        );
        // Not linked to Ann: nothing to get it from.
        assert_eq!(debug.buttons, []);
        // Linked: get it from her.
        let linked = analysis_banner(Some(&mine), &theirs, &[key(2)], None).unwrap();
        assert_eq!(
            linked.buttons,
            [Button {
                label: "Get it from Ann".to_owned(),
                action: Action::FetchDebug(key(2)),
            }]
        );
        // While it comes, the banner says how far.
        let fetching = Fetching {
            name: "libfoo.debug".to_owned(),
            from: key(2),
            debug: true,
            opening: false,
            done: 1_500_000,
            total: 6_000_000,
        };
        let coming = analysis_banner(Some(&mine), &theirs, &[key(2)], Some(&fetching)).unwrap();
        assert_eq!(
            (coming.text.as_str(), coming.tone, coming.buttons.len()),
            (
                "Getting libfoo.debug from Ann: 1.5 MB of 6.0 MB (25 %)",
                Tone::Busy,
                0
            )
        );
        // Without a debug file of theirs, nothing to get: another fingerprint.
        let other =
            analysis_banner(Some(&mine), &[person([2; 32], None)], &[key(2)], None).unwrap();
        assert!(other.text.starts_with("Your analysis differs from Ann's"));
        assert_eq!(other.buttons, []);
    }
}
