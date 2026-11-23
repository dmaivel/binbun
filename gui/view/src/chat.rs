//! The chat's messages: the
//! places a message names, found once as it is sent ([`links`]), so a
//! later rename keeps them, and how a message shows them ([`shown`]).
//!
//! - **Addresses** link only when mapped in the image (as Go To finds
//!   them) and written as hex of four or more digits: bare with a letter
//!   and a digit (`1E720`), the `h`-suffixed `1E720h` (a decimal digit
//!   first), C's `0x1E720`, or zero-padded as a listing prints them
//!   (`0000000000401000`). A number that reads as decimal (`2048`,
//!   `100000`), short hex (`0x48`, `E72`) and words of hex letters
//!   (`added`, `cafe`) stay plain; in backticks any hex of four or more
//!   digits links.
//! - **Names** that exist link when code-shaped: an underscore, a digit,
//!   mixed case (`pushStream`; a capital first letter alone is not), `::`,
//!   `name+off`, `name()`; or in backticks. An ordinary word that is a
//!   name (`free`, `read`) is a link only while Ctrl is held
//!   ([`ChatLink::word`]: an uncertain link needs the modifier).
//!   A word after `@` (a mention) or `#`, and anything in a URL, is left.
//! - What does not resolve stays plain. Text in backticks shows in the
//!   code font, the backticks dropped.
//! - **Insert Location**'s text ([`location_text`]) links whole to the
//!   place it was inserted for while it stays as inserted.

use std::ops::Range;

/// The fewest hex digits an address is written with.
const DIGITS: usize = 4;

/// The fewest digits of an address written zero-padded, as a listing
/// prints them.
const PADDED: usize = 8;

/// The most hex digits of an address (64 bits).
const MOST: usize = 16;

/// A place a message's text names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatLink {
    /// The text's bytes naming it.
    pub range: Range<usize>,
    /// Where it goes.
    pub address: u64,
    /// An ordinary word that is a name (`free`): a link only while Ctrl
    /// is held.
    pub word: bool,
}

/// What a message's places are looked up in: the image the session
/// shares, with the user's names.
pub trait Places {
    /// The address `name` names, if it is a name (not an address written
    /// out).
    fn named(&self, name: &str) -> Option<u64>;
    /// Whether `address` is mapped in the image.
    fn mapped(&self, address: u64) -> bool;
}

/// The places `text` names, in text order: each of `inserted` (Insert
/// Location's text and its address) where it still stands whole, then
/// what backticks hold, then the addresses and names found by the rules
/// of the module's documentation.
pub fn links(text: &str, inserted: &[(String, u64)], places: &impl Places) -> Vec<ChatLink> {
    let mut out: Vec<ChatLink> = Vec::new();
    for (shown, address) in inserted {
        let free = text
            .match_indices(shown.as_str())
            .map(|(at, s)| at..at + s.len())
            .find(|range| !range.is_empty() && !taken(&out, range));
        if let Some(range) = free {
            out.push(ChatLink {
                range,
                address: *address,
                word: false,
            });
        }
    }
    let spans = code_spans(text);
    for span in &spans {
        let inner = span.start + 1..span.end - 1;
        let content = text.get(inner.clone()).unwrap_or_default();
        let lead = content.len() - content.trim_start().len();
        let range = inner.start + lead..inner.start + lead + content.trim().len();
        if taken(&out, span) {
            continue;
        }
        if let Some(address) = code_place(content.trim(), places) {
            out.push(ChatLink {
                range,
                address,
                word: false,
            });
        }
    }
    for token in tokens(text) {
        if taken(&out, &token) || spans.iter().any(|span| overlap(span, &token)) {
            continue;
        }
        if let Some(link) = token_link(text, token, places) {
            out.push(link);
        }
    }
    out.sort_by_key(|link| link.range.start);
    out
}

/// What Insert Location writes for `address`: the name of the function
/// or item holding it, a middle dot and the address (`push_stream ·
/// 1E720`), or the address alone where nothing named holds it.
pub fn location_text(name: Option<&str>, address: u64) -> String {
    match name {
        Some(name) => format!("{name} \u{b7} {address:X}"),
        None => format!("{address:X}"),
    }
}

/// Whether `range` meets a link of `links`.
fn taken(links: &[ChatLink], range: &Range<usize>) -> bool {
    links.iter().any(|link| overlap(&link.range, range))
}

fn overlap(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

/// The code spans of `text`: a backtick to the next on its line, with
/// something between, each with its backticks.
fn code_spans(text: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut open: Option<usize> = None;
    for (i, c) in text.char_indices() {
        match (c, open) {
            ('`', None) => open = Some(i),
            ('`', Some(start)) => {
                if i > start + 1 {
                    out.push(start..i + 1);
                }
                open = None;
            }
            ('\n', Some(_)) => open = None,
            _ => {}
        }
    }
    out
}

/// Whether `c` belongs to a word that may be a name or an address.
fn word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

/// The words of `text` that may name a place: runs of [`word_char`]s,
/// joined across `.` and `::` with more after them (`sub_1000.cold`,
/// `std::vector`); none after `@` or `#`, none in a URL.
fn tokens(text: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut previous: Option<char> = None;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let next = chars.peek().map(|&(_, n)| n);
        let joins = start.is_some()
            && match c {
                '.' => next.is_some_and(word_char),
                ':' => next == Some(':') || (previous == Some(':') && next.is_some_and(word_char)),
                _ => false,
            };
        if word_char(c) || joins {
            if start.is_none() && !matches!(previous, Some('@' | '#')) {
                start = Some(i);
            } else if start.is_none() {
                // After `@` or `#`: skipped to its end.
                start = Some(usize::MAX);
            }
        } else if let Some(s) = start.take()
            && s != usize::MAX
        {
            out.push(s..i);
        }
        previous = Some(c);
    }
    if let Some(s) = start
        && s != usize::MAX
    {
        out.push(s..text.len());
    }
    out.retain(|token| !in_url(text, token));
    out
}

/// Whether `token` is part of a URL: its whitespace-delimited chunk holds
/// `://`.
fn in_url(text: &str, token: &Range<usize>) -> bool {
    let before = text.get(..token.start).unwrap_or_default();
    let after = text.get(token.start..).unwrap_or_default();
    let from = before.rfind(char::is_whitespace).map_or(0, |i| i + 1);
    let to = after
        .find(char::is_whitespace)
        .map_or(text.len(), |i| token.start + i);
    text.get(from..to)
        .is_some_and(|chunk| chunk.contains("://"))
}

/// The address `word` writes, by the module's rules (`code`: in
/// backticks, where a bare number of four or more digits is hex).
fn address_of(word: &str, code: bool) -> Option<u64> {
    if let Some(hex) = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X")) {
        return hex_of(hex);
    }
    if let Some(hex) = word.strip_suffix('h').or_else(|| word.strip_suffix('H'))
        && hex.starts_with(|c: char| c.is_ascii_digit())
    {
        return hex_of(hex);
    }
    let letters = word.chars().any(|c| c.is_ascii_alphabetic());
    let digits = word.chars().any(|c| c.is_ascii_digit());
    let padded = !letters && word.len() >= PADDED && word.starts_with('0');
    if code || (letters && digits) || padded {
        hex_of(word)
    } else {
        None
    }
}

/// `hex` read as an address: [`DIGITS`] to [`MOST`] hex digits.
fn hex_of(hex: &str) -> Option<u64> {
    if !(DIGITS..=MOST).contains(&hex.len()) || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

/// An offset after a name's `+`: hex, written any of the ways an address
/// is, of any length.
fn offset_of(word: &str) -> Option<u64> {
    let hex = word
        .strip_prefix("0x")
        .or_else(|| word.strip_prefix("0X"))
        .or_else(|| word.strip_suffix('h'))
        .unwrap_or(word);
    if hex.is_empty() || hex.len() > MOST || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

/// Whether `name` looks like code: an underscore, a digit, `::`, or mixed
/// case (a capital after a first letter, with small letters).
fn code_shaped(name: &str) -> bool {
    name.contains('_')
        || name.contains("::")
        || name.chars().any(|c| c.is_ascii_digit())
        || (name.chars().skip(1).any(char::is_uppercase) && name.chars().any(char::is_lowercase))
}

/// What backticks hold, as a place: an address, a name, `name+off` or
/// `name()`.
fn code_place(content: &str, places: &impl Places) -> Option<u64> {
    if let Some(address) = address_of(content, true).filter(|&a| places.mapped(a)) {
        return Some(address);
    }
    let content = content.strip_suffix("()").unwrap_or(content);
    if let Some((name, offset)) = content.rsplit_once('+')
        && let Some(offset) = offset_of(offset)
        && let Some(base) = places.named(name)
    {
        return base.checked_add(offset);
    }
    places.named(content)
}

/// The link of word `token` of `text`, if it names a place: an address,
/// or a name, with an offset (`+3A`) or a call's parentheses after it.
fn token_link(text: &str, token: Range<usize>, places: &impl Places) -> Option<ChatLink> {
    let word = text.get(token.clone())?;
    if let Some(address) = address_of(word, false).filter(|&a| places.mapped(a)) {
        return Some(ChatLink {
            range: token,
            address,
            word: false,
        });
    }
    if word.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let after = text.get(token.end..).unwrap_or_default();
    let offset = after.strip_prefix('+').and_then(|rest| {
        let len = rest.find(|c: char| !word_char(c)).unwrap_or(rest.len());
        Some((len + 1, offset_of(rest.get(..len)?)?))
    });
    let (end, offset, shaped) = match offset {
        Some((len, offset)) => (token.end + len, offset, true),
        None if after.starts_with("()") => (token.end + 2, 0, true),
        None => (token.end, 0, code_shaped(word)),
    };
    let address = places.named(word)?.checked_add(offset)?;
    Some(ChatLink {
        range: token.start..end,
        address,
        word: !shaped,
    })
}

/// A message as shown: its text with the backticks of code spans dropped,
/// and the pieces of it drawn apart.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shown {
    /// The text shown.
    pub text: String,
    /// The pieces drawn apart, in order, apart from one another.
    pub pieces: Vec<Piece>,
}

/// A piece of a message drawn apart: code, (part of) a link, a mention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Piece {
    /// Its bytes in [`Shown::text`].
    pub range: Range<usize>,
    /// In backticks: the code font.
    pub code: bool,
    /// Part of a link: its number among the message's links, where it
    /// goes, and whether it is an ordinary word (Ctrl only).
    pub link: Option<(usize, u64, bool)>,
    /// A mention: of this person (`true`) or of another.
    pub mention: Option<bool>,
}

/// `text` as shown, with its `links` and its `mentions` (ranges, and
/// whether each is of this person); links and mentions that are not
/// ranges of the text between characters, or meet one before them, are
/// left out.
pub fn shown(text: &str, links: &[ChatLink], mentions: &[(Range<usize>, bool)]) -> Shown {
    let fits = |range: &Range<usize>| range.start < range.end && text.get(range.clone()).is_some();
    let mut kept: Vec<(usize, &ChatLink)> = links
        .iter()
        .enumerate()
        .filter(|(_, link)| fits(&link.range))
        .collect();
    kept.sort_by_key(|(_, link)| link.range.start);
    let mut end = 0;
    kept.retain(|(_, link)| {
        let apart = link.range.start >= end;
        if apart {
            end = link.range.end;
        }
        apart
    });
    let mentions: Vec<&(Range<usize>, bool)> = mentions.iter().filter(|(r, _)| fits(r)).collect();
    let spans = code_spans(text);
    let ticks: Vec<usize> = spans.iter().flat_map(|s| [s.start, s.end - 1]).collect();
    let mut cuts = vec![0, text.len()];
    cuts.extend(
        spans
            .iter()
            .flat_map(|s| [s.start, s.start + 1, s.end - 1, s.end]),
    );
    cuts.extend(kept.iter().flat_map(|(_, l)| [l.range.start, l.range.end]));
    cuts.extend(mentions.iter().flat_map(|(r, _)| [r.start, r.end]));
    cuts.sort_unstable();
    cuts.dedup();
    let shown_at = |at: usize| at - ticks.iter().filter(|&&t| t < at).count();
    let mut pieces = Vec::new();
    for pair in cuts.windows(2) {
        let &[a, b] = pair else {
            continue;
        };
        if ticks.contains(&a) {
            continue;
        }
        let code = spans.iter().any(|s| s.start < a && b < s.end);
        let link = kept
            .iter()
            .find(|(_, l)| l.range.start <= a && b <= l.range.end)
            .map(|&(n, l)| (n, l.address, l.word));
        let mention = mentions
            .iter()
            .find(|(r, _)| r.start <= a && b <= r.end)
            .map(|(_, me)| *me);
        if code || link.is_some() || mention.is_some() {
            pieces.push(Piece {
                range: shown_at(a)..shown_at(b),
                code,
                link,
                mention,
            });
        }
    }
    let text = text
        .char_indices()
        .filter(|(i, _)| !ticks.contains(i))
        .map(|(_, c)| c)
        .collect();
    Shown { text, pieces }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{ChatLink, Piece, Places, links, location_text, shown};

    /// An image mapped from `0x1000` to `0x40_0000` (and a page at
    /// `0x40_1000`, as a non-PIE binary's text), with a few names.
    struct Image(HashMap<&'static str, u64>);

    impl Image {
        fn new() -> Self {
            Self(HashMap::from([
                ("push_stream", 0x1E700),
                ("main", 0x1130),
                ("free", 0x1040),
                ("read", 0x1050),
                ("GetProcAddress", 0x2000),
                ("std::vector", 0x3000),
                ("sub_1E720", 0x1E720),
            ]))
        }
    }

    impl Places for Image {
        fn named(&self, name: &str) -> Option<u64> {
            self.0.get(name).copied()
        }

        fn mapped(&self, address: u64) -> bool {
            (0x1000..0x40_0000).contains(&address) || (0x40_1000..0x40_2000).contains(&address)
        }
    }

    /// What `text`'s links name: the words and where they go, Ctrl-only
    /// words marked.
    fn found(text: &str) -> Vec<(&str, u64, bool)> {
        links(text, &[], &Image::new())
            .into_iter()
            .map(|l| (text.get(l.range).unwrap(), l.address, l.word))
            .collect()
    }

    #[test]
    fn addresses_and_code_shaped_names_link_when_they_exist() {
        assert_eq!(
            found("crash at 1E720, 0x1E724 or 1E728h; in push_stream+3A, sub_1E720()."),
            [
                ("1E720", 0x1E720, false),
                ("0x1E724", 0x1E724, false),
                ("1E728h", 0x1E728, false),
                ("push_stream+3A", 0x1E73A, false),
                ("sub_1E720()", 0x1E720, false),
            ]
        );
        assert_eq!(
            found("GetProcAddress and std::vector, the listing's 0000000000401000"),
            [
                ("GetProcAddress", 0x2000, false),
                ("std::vector", 0x3000, false),
                ("0000000000401000", 0x40_1000, false),
            ]
        );
        // `name()` and `name+off` make an ordinary word code.
        assert_eq!(
            found("free() then main+58"),
            [("free()", 0x1040, false), ("main+58", 0x1188, false)]
        );
    }

    #[test]
    fn prose_numbers_short_hex_and_strangers_stay_plain() {
        for text in [
            // Words of hex letters, prose.
            "I added a face to the cafe; dead beef, decade, accede",
            // Short hex, in every form.
            "add 0x48 to rsp, E72 or 1E7 or 0FFh",
            // Decimal numbers, dates, versions, sizes.
            "2048 bytes, 100000 times on 2026-11-13 with v1.2.3, 4096",
            // Unmapped addresses; names that do not exist.
            "0xFFFF0000 and 9ABCDEF0h; do_thing and parseHeader",
            // A capital first letter or capitals alone are no code.
            "Main says FREE",
            // After `@` or `#`, in a URL.
            "@sub_1E720 #1E720 https://example.org/1E720/push_stream",
        ] {
            assert_eq!(found(text), [], "{text}");
        }
    }

    #[test]
    fn an_ordinary_word_that_is_a_name_links_only_while_ctrl_is_held() {
        assert_eq!(
            found("free the buffer, then read it in main"),
            [
                ("free", 0x1040, true),
                ("read", 0x1050, true),
                ("main", 0x1130, true),
            ]
        );
    }

    #[test]
    fn backticks_make_any_existing_name_or_hex_a_link() {
        assert_eq!(
            found("`free` and ` read ` at `1000`, `main+8`, `2048` `nope`"),
            [
                ("free", 0x1040, false),
                ("read", 0x1050, false),
                ("1000", 0x1000, false),
                ("main+8", 0x1138, false),
                ("2048", 0x2048, false),
            ]
        );
        // An empty pair, or a pair across lines, is no code.
        assert_eq!(
            found("``free and `main\nfree`"),
            [
                ("free", 0x1040, true),
                ("main", 0x1130, true),
                ("free", 0x1040, true),
            ]
        );
    }

    #[test]
    fn insert_locations_text_links_whole_while_it_stays_as_inserted() {
        let place = location_text(Some("push_stream"), 0x1E75A);
        assert_eq!(place, "push_stream \u{b7} 1E75A");
        assert_eq!(location_text(None, 0x1E75A), "1E75A");
        let placed = [(place.clone(), 0x1E75A)];
        let text = format!("look at {place} and 0x1E720");
        let got = links(&text, &placed, &Image::new());
        let at = text.find(&place).unwrap();
        assert_eq!(
            got,
            [
                ChatLink {
                    range: at..at + place.len(),
                    address: 0x1E75A,
                    word: false,
                },
                ChatLink {
                    range: text.find("0x").unwrap()..text.len(),
                    address: 0x1E720,
                    word: false,
                },
            ]
        );
        // Edited, it is no longer the inserted place: its parts link by
        // the rules.
        let edited = "look at push_stream \u{b7} 1E7";
        assert_eq!(
            links(edited, &placed, &Image::new())
                .iter()
                .map(|l| (edited.get(l.range.clone()).unwrap(), l.address))
                .collect::<Vec<_>>(),
            [("push_stream", 0x1E700)]
        );
    }

    #[test]
    fn a_message_shows_code_without_its_backticks_links_and_mentions_apart() {
        let text = "@Bob see `push_stream+3A` and main, `x`";
        let link = |range, address, word| ChatLink {
            range,
            address,
            word,
        };
        let links = [
            link(10..24, 0x1E73A, false),
            link(30..34, 0x1130, true),
            // Out of the text, over the one before: left out.
            link(30..90, 1, false),
            link(20..28, 2, false),
        ];
        let got = shown(text, &links, &[(0..4, true)]);
        assert_eq!(got.text, "@Bob see push_stream+3A and main, x");
        let piece = |range, code, link, mention| Piece {
            range,
            code,
            link,
            mention,
        };
        assert_eq!(
            got.pieces,
            [
                piece(0..4, false, None, Some(true)),
                piece(9..23, true, Some((0, 0x1E73A, false)), None),
                piece(28..32, false, Some((1, 0x1130, true)), None),
                piece(34..35, true, None, None),
            ]
        );
        assert_eq!(got.text.get(9..23), Some("push_stream+3A"));
        let multibyte = shown("é `a`", &[link(1..2, 3, false)], &[]);
        assert_eq!(multibyte.text, "é a");
        assert_eq!(multibyte.pieces, [piece(3..4, true, None, None)]);
    }
}
