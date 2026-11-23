//! Range selections (the selection synchronised with the listing and
//! the C view). The listing selects whole lines, as a disassembler
//! does ([`Lines`]); the C selects characters across lines, as an editor
//! does ([`Text`]). Each keeps its fixed end (the anchor); the moving end
//! is the view's cursor. A drag moves the cursor from where the button
//! went down; Shift with a click or a key extends from the cursor; a plain
//! click, a key without Shift or Escape drops it.
//!
//! Also here: what Copy takes ([`listing_text`], [`c_text`]), the bytes a
//! listing selection's items hold ([`listing_bytes`]) and the lines that
//! show some addresses' items ([`item_lines`]), for the hex view and the
//! others' selections, and the instructions behind C lines
//! ([`line_addresses`]), for the provenance wash.

use std::ops::RangeInclusive;

use binbun::Database;

use crate::cdoc::CDocument;
use crate::listing::{Listing, Overlay};

/// The most lines Copy takes from the listing.
pub const MOST_COPIED: u64 = 1 << 16;

/// The most lines of one item [`item_lines`] walks over to find its first
/// and last.
const ITEM_LINES: u64 = 256;

/// A selection of whole lines, from the anchor to the cursor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lines {
    /// The fixed end, while lines are selected.
    pub anchor: Option<u64>,
    /// The line a drag goes from, while the button is down.
    pub pressed: Option<u64>,
}

impl Lines {
    /// The lines selected with the cursor on `cursor`, in order.
    pub fn range(&self, cursor: u64) -> Option<RangeInclusive<u64>> {
        let anchor = self.anchor?;
        Some(anchor.min(cursor)..=anchor.max(cursor))
    }

    /// The cursor leaves `cursor` by a key or a click: with `extend`
    /// (Shift) the selection grows from it, else it goes.
    pub fn leave(&mut self, cursor: u64, extend: bool) {
        if extend {
            self.anchor.get_or_insert(cursor);
        } else {
            self.anchor = None;
        }
    }

    /// The button went down on line `at`, the cursor on `cursor`: with
    /// `extend` the selection grows from the cursor and a drag goes on from
    /// its anchor; else it goes, and a drag from `at` may select.
    pub fn press(&mut self, at: u64, cursor: u64, extend: bool) {
        self.leave(cursor, extend);
        self.pressed = Some(self.anchor.unwrap_or(at));
    }

    /// The pointer is dragged onto line `at`: whether the cursor follows
    /// it, selecting from the line pressed (once it has left that line).
    pub fn drag(&mut self, at: u64) -> bool {
        let Some(pressed) = self.pressed else {
            return false;
        };
        if self.anchor.is_none() && at == pressed {
            return false;
        }
        self.anchor.get_or_insert(pressed);
        true
    }

    /// The button is up: dragging ends, the selection stays.
    pub fn release(&mut self) {
        self.pressed = None;
    }

    /// Drops the selection; whether there was one.
    pub fn clear(&mut self) -> bool {
        self.pressed = None;
        self.anchor.take().is_some()
    }
}

/// A place in the C's text: a line and a column in characters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextPos {
    /// The line.
    pub line: usize,
    /// The column, in characters.
    pub column: usize,
}

impl TextPos {
    /// Column `column` of line `line`.
    pub const fn new(line: usize, column: usize) -> Self {
        Self { line, column }
    }
}

/// A selection of characters, from the anchor to the cursor (the end
/// excluded).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Text {
    /// The fixed end, while characters are selected (or the button is
    /// down).
    pub anchor: Option<TextPos>,
    /// The button is down: a drag moves the cursor.
    pub pressed: bool,
}

impl Text {
    /// The characters selected with the cursor at `cursor`: where they
    /// start and where they end (excluded); none if none are.
    pub fn range(&self, cursor: TextPos) -> Option<(TextPos, TextPos)> {
        let anchor = self.anchor?;
        (anchor != cursor).then(|| (anchor.min(cursor), anchor.max(cursor)))
    }

    /// The lines the selection touches with the cursor at `cursor` (a
    /// selection ending at a line's first column does not touch it).
    pub fn lines(&self, cursor: TextPos) -> Option<RangeInclusive<usize>> {
        let (from, to) = self.range(cursor)?;
        let last = if to.column == 0 && to.line > from.line {
            to.line - 1
        } else {
            to.line
        };
        Some(from.line..=last)
    }

    /// The cursor leaves `cursor` by a key or a click: with `extend`
    /// (Shift) the selection grows from it, else it goes.
    pub fn leave(&mut self, cursor: TextPos, extend: bool) {
        if extend {
            self.anchor.get_or_insert(cursor);
        } else {
            self.anchor = None;
        }
    }

    /// The button went down at `at`, the cursor at `cursor`: with `extend`
    /// the selection grows from the cursor, else a new one starts at `at`
    /// (empty until dragged).
    pub fn press(&mut self, at: TextPos, cursor: TextPos, extend: bool) {
        if extend {
            self.anchor.get_or_insert(cursor);
        } else {
            self.anchor = Some(at);
        }
        self.pressed = true;
    }

    /// The button is up with the cursor at `cursor`: dragging ends; an
    /// empty selection goes (so the cursor moving later selects nothing).
    pub fn release(&mut self, cursor: TextPos) {
        self.pressed = false;
        if self.anchor == Some(cursor) {
            self.anchor = None;
        }
    }

    /// Drops the selection with the cursor at `cursor`; whether anything
    /// was selected.
    pub fn clear(&mut self, cursor: TextPos) -> bool {
        let had = self.range(cursor).is_some();
        self.anchor = None;
        self.pressed = false;
        had
    }
}

/// The byte of `text` at character `column` (its end past the last).
pub fn byte_at(text: &str, column: usize) -> usize {
    text.char_indices()
        .nth(column)
        .map_or(text.len(), |(b, _)| b)
}

/// The character column of byte `byte` of `text`.
pub fn column_at(text: &str, byte: usize) -> usize {
    text.get(..byte)
        .map_or_else(|| text.chars().count(), |t| t.chars().count())
}

/// The token at `at` in `document` (a double click): its span's
/// characters, else the run of word characters, of spaces, or the one
/// other character there.
pub fn c_token(document: &CDocument, at: TextPos) -> (TextPos, TextPos) {
    let text = document.line_text(at.line);
    let byte = byte_at(text, at.column);
    let start = document.lines.get(at.line).map_or(0, |l| l.range.start);
    let span = document
        .span_at(at.line, byte)
        .and_then(|s| document.spans.get(s))
        .map(|s| (s.range.start - start, s.range.end - start));
    let (from, to) = span.unwrap_or_else(|| word_at(text, byte));
    (
        TextPos::new(at.line, column_at(text, from)),
        TextPos::new(at.line, column_at(text, to)),
    )
}

/// The bytes of the word, the spaces or the one other character at byte
/// `byte` of `text` (none past its end).
fn word_at(text: &str, byte: usize) -> (usize, usize) {
    let Some(c) = text.get(byte..).and_then(|t| t.chars().next()) else {
        return (text.len(), text.len());
    };
    let class = |c: char| {
        if c.is_alphanumeric() || c == '_' {
            0
        } else if c.is_whitespace() {
            1
        } else {
            2
        }
    };
    let kind = class(c);
    if kind == 2 {
        return (byte, byte + c.len_utf8());
    }
    let before = text.get(..byte).unwrap_or("");
    let after = text.get(byte..).unwrap_or("");
    let from = before
        .char_indices()
        .rev()
        .take_while(|&(_, c)| class(c) == kind)
        .last()
        .map_or(byte, |(b, _)| b);
    let to = after
        .char_indices()
        .find(|&(_, c)| class(c) != kind)
        .map_or(text.len(), |(b, _)| byte + b);
    (from, to)
}

/// Line `line` of `document` whole (a triple click): to the next line's
/// start, or to its end on the last line.
pub fn c_line(document: &CDocument, line: usize) -> (TextPos, TextPos) {
    let to = if line + 1 < document.lines.len() {
        TextPos::new(line + 1, 0)
    } else {
        TextPos::new(line, document.line_text(line).chars().count())
    };
    (TextPos::new(line, 0), to)
}

/// The text of `document` from `from` to `to` (excluded), its lines
/// broken by `\n`; columns past a line's end are at its end.
pub fn c_text(document: &CDocument, from: TextPos, to: TextPos) -> String {
    let mut out = String::new();
    for n in from.line..=to.line.min(document.lines.len().saturating_sub(1)) {
        let text = document.line_text(n);
        let start = if n == from.line {
            byte_at(text, from.column)
        } else {
            0
        };
        let end = if n == to.line {
            byte_at(text, to.column)
        } else {
            text.len()
        };
        out.push_str(text.get(start..end.max(start)).unwrap_or(""));
        if n < to.line {
            out.push('\n');
        }
    }
    out
}

/// The instructions behind `lines` of `document`, sorted, each once.
pub fn line_addresses(document: &CDocument, lines: RangeInclusive<usize>) -> Vec<u64> {
    let mut out: Vec<u64> = document
        .lines
        .get(lines)
        .into_iter()
        .flatten()
        .flat_map(|l| l.addresses.iter().copied())
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The columns of line `line` (`len` characters) the characters from
/// `from` to `to` (excluded) take, as drawn: a line they go on past also
/// takes a column after its end, its line break; none if they take none.
pub fn columns_on(
    (from, to): (TextPos, TextPos),
    line: usize,
    len: usize,
) -> Option<(usize, usize)> {
    if line < from.line || line > to.line {
        return None;
    }
    let start = if line == from.line {
        from.column.min(len)
    } else {
        0
    };
    let end = if line == to.line {
        to.column.min(len)
    } else {
        len + 1
    };
    (start < end).then_some((start, end))
}

/// The text of `lines` of `listing` as shown, a line each (at most
/// [`MOST_COPIED`]), each line's trailing spaces dropped.
pub fn listing_text(
    listing: &Listing,
    db: &Database<'_>,
    overlay: &Overlay,
    lines: RangeInclusive<u64>,
) -> String {
    let (first, last) = (*lines.start(), *lines.end());
    let last = last
        .min(first.saturating_add(MOST_COPIED - 1))
        .min(listing.len().saturating_sub(1));
    let mut out = String::new();
    for n in first..=last {
        if n > first {
            out.push('\n');
        }
        let rendered = listing.render(db, n, overlay);
        let start = out.len();
        for token in &rendered.tokens {
            out.push_str(&token.text);
        }
        let kept = out.get(start..).map_or(0, |line| line.trim_end().len());
        out.truncate(start + kept);
    }
    out
}

/// The bytes the items of `lines` hold: from the first line's item's
/// address to past the last line's item (its first byte at least).
pub fn listing_bytes(listing: &Listing, lines: RangeInclusive<u64>) -> Option<(u64, u64)> {
    let first = listing.line(*lines.start())?.address;
    let last = listing.line(*lines.end())?.address;
    let end = listing
        .lines()
        .spans(last..last.saturating_add(1))
        .into_iter()
        .find(|s| s.start <= last && last < s.end)
        .map_or(last.saturating_add(1), |s| s.end);
    Some((first, end.max(first.saturating_add(1))))
}

/// The lines showing the items holding `first` to `last`: from the first
/// line of `first`'s item (its header and label lines too) to the last of
/// `last`'s.
pub fn item_lines(listing: &Listing, first: u64, last: u64) -> RangeInclusive<u64> {
    let address = |n: u64| listing.line(n).map(|l| l.address);
    let mut start = listing.line_of(first);
    let head = address(start);
    for _ in 0..ITEM_LINES {
        match start.checked_sub(1) {
            Some(before) if address(before) == head => start = before,
            Some(_) | None => break,
        }
    }
    let mut end = listing.line_of(last).max(start);
    let tail = address(end);
    for _ in 0..ITEM_LINES {
        if end + 1 < listing.len() && address(end + 1) == tail {
            end += 1;
        } else {
            break;
        }
    }
    start..=end
}

#[cfg(test)]
mod tests;
