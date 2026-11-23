//! Data items: what bytes are, their lines.

use std::collections::BTreeSet;

use crate::Database;
use crate::corrections::{Data, Unit};
use crate::listing::build::Builder;
use crate::listing::render::{bytes, read};
use crate::listing::text::{COMMENTS, MNEMONIC, STRING_WRAP, number};
use crate::listing::{
    DataItem, DataKind, Decoder, Item, LineKind, Listing, Numbers, Rendered, Role,
};
use crate::references::Kind;

/// The longest run of one byte value written as single bytes.
const SHORT_RUN: u64 = 3;
/// The largest alignment written as `align` (the alignment of sections
/// compilers emit for AVX data and code).
const MAX_ALIGN: u64 = 0x20;

/// Lays out the bytes `start..end` as data (those from `file_end` on
/// uninitialised): items cut where something starts (a string, a
/// pointer, an import slot, an object, a table; outside objects and
/// strings, a referenced or named address).
pub(crate) fn lay_out(b: &mut Builder<'_, '_>, start: u64, end: u64, file_end: u64) {
    let cuts = cuts(b, start, end, file_end);
    let dynamic = b
        .dynamic
        .as_ref()
        .is_some_and(|d| d.start == start && d.end == end);
    let mut a = start;
    let mut object_end = start;
    while a < end {
        if dynamic && a < file_end {
            // ELF's dynamic section: `Elf64_Dyn`/`Elf32_Dyn` entries, a
            // tag and a value each, one entry a line.
            let width = b.l.pointer_size;
            let size = file_end - a;
            push(
                b,
                DataItem {
                    start: a,
                    size,
                    kind: DataKind::Values { width },
                },
            );
            a += size;
            continue;
        }
        if let Some(&size) = b.objects.get(&a) {
            object_end = a.saturating_add(size);
        }
        let next = cuts.range(a + 1..).next().copied().unwrap_or(end).min(end);
        let item = classify(b, a, next, end, file_end, object_end);
        push(b, item);
        a = item.start + item.size.max(1);
    }
}

/// Where items must start in `start..end`.
fn cuts(b: &Builder<'_, '_>, start: u64, end: u64, file_end: u64) -> BTreeSet<u64> {
    // Inside an object or a string, only what has bytes of its own cuts.
    let inside = |at: u64| {
        let object = b
            .objects
            .range(..at)
            .next_back()
            .is_some_and(|(&s, &n)| at < s.saturating_add(n));
        let string = b
            .strings
            .range(..at)
            .next_back()
            .is_some_and(|(&s, &(n, _))| at < s.saturating_add(n));
        object || string
    };
    let mut cuts = BTreeSet::from([file_end]);
    let mut add = |at: u64, size: u64| {
        cuts.insert(at);
        cuts.insert(at.saturating_add(size));
    };
    for (&at, &(size, _)) in b.strings.range(start..end) {
        add(at, size);
    }
    let first = b.image.pointers.partition_point(|p| p.at < start);
    for p in b
        .image
        .pointers
        .get(first..)
        .unwrap_or_default()
        .iter()
        .take_while(|p| p.at < end)
    {
        add(p.at, u64::from(b.l.pointer_size));
    }
    for (&at, &index) in b.slots.range(start..end) {
        let size = b
            .image
            .imports
            .get(index as usize)
            .map_or(8, |i| u64::from(i.size));
        add(at, size);
    }
    for (&at, &size) in b.objects.range(start..end) {
        add(at, size);
    }
    for (&at, t) in b.tables.range(start..end) {
        add(at, t.count * u64::from(t.width));
    }
    for (&at, &width) in b.widths.range(start..end) {
        if !inside(at) {
            cuts.insert(at);
            if !inside(at + u64::from(width)) {
                cuts.insert(at + u64::from(width));
            }
        }
    }
    for r in b.refs.within(start..end) {
        if !inside(r.target) {
            cuts.insert(r.target);
        }
    }
    for &at in b.l.names.range(start..end).map(|(at, _)| at) {
        if !inside(at) {
            cuts.insert(at);
        }
    }
    // The user's items: nothing cuts inside one.
    for (at, item_end) in b.user_items(start, end) {
        let within: Vec<u64> = cuts
            .range(at.saturating_add(1)..item_end)
            .copied()
            .collect();
        for cut in within {
            cuts.remove(&cut);
        }
        cuts.insert(at.max(start));
        cuts.insert(item_end.min(end));
    }
    cuts
}

/// The item at `a`, before the next cut `next`.
fn classify(
    b: &Builder<'_, '_>,
    a: u64,
    next: u64,
    end: u64,
    file_end: u64,
    object_end: u64,
) -> DataItem {
    let item = |size: u64, kind| DataItem {
        start: a,
        size,
        kind,
    };
    if let Some((at, item_end, data)) = b.user_item(a) {
        return user(a, next.min(item_end), at, data, file_end, b);
    }
    // An object's size, if it is one value; else the width code accesses
    // it at.
    let width = match b.objects.get(&a) {
        Some(&size) => u8::try_from(size)
            .ok()
            .filter(|s| matches!(s, 1 | 2 | 4 | 8 | 16)),
        None => b.widths.get(&a).copied().filter(|&w| w > 0),
    }
    .filter(|&w| a + u64::from(w) <= next);
    if a >= file_end {
        let bare = a >= object_end && b.refs.to(a).is_empty() && !b.l.names.contains_key(&a);
        return match (width, alignment(a, next)) {
            (Some(w), _) => item(u64::from(w), DataKind::Uninitialised { width: w }),
            (None, Some(to)) if bare => item(next - a, DataKind::Align { to }),
            (None, Some(_) | None) => item(next - a, DataKind::Uninitialised { width: 0 }),
        };
    }
    if let Some(t) = b.tables.get(&a) {
        let size = (t.count * u64::from(t.width)).min(end - a);
        return item(
            size,
            DataKind::Table {
                width: t.width,
                relative: t.relative,
            },
        );
    }
    if let Some(&(size, wide)) = b.strings.get(&a)
        && a + size <= end
    {
        return item(size, DataKind::String { wide });
    }
    if let Some(&index) = b.slots.get(&a) {
        let size = b
            .image
            .imports
            .get(index as usize)
            .map_or(8, |i| u64::from(i.size));
        if a + size <= end {
            return item(size, DataKind::Import { index });
        }
    }
    let size = u64::from(b.l.pointer_size);
    if let Ok(i) = b.image.pointers.binary_search_by_key(&a, |p| p.at)
        && a + size <= end
        && let Some(p) = b.image.pointers.get(i)
    {
        return item(size, DataKind::Pointer { target: p.target });
    }
    if let Some(w) = width {
        return item(u64::from(w), DataKind::Scalar { width: w });
    }
    if a < object_end {
        let size = next.min(object_end) - a;
        let width = [8u8, 4, 2]
            .into_iter()
            .find(|&w| a.is_multiple_of(u64::from(w)) && size.is_multiple_of(u64::from(w)))
            .unwrap_or(1);
        return item(size, DataKind::Values { width });
    }
    unexplored(b, a, next)
}

/// The user's item at `a` (starting at `at`), before `next`: its data
/// (one value, an array of values, a string), else bytes nothing types
/// ([`unexplored`]); from `file_end` on, uninitialised.
fn user(
    a: u64,
    next: u64,
    at: u64,
    data: Option<Data>,
    file_end: u64,
    b: &Builder<'_, '_>,
) -> DataItem {
    let size = next.saturating_sub(a).max(1);
    let item = |kind| DataItem {
        start: a,
        size,
        kind,
    };
    let Some(data) = data.filter(|_| at == a) else {
        return if a >= file_end {
            item(DataKind::Uninitialised { width: 0 })
        } else {
            unexplored(b, a, a + size)
        };
    };
    let width = u8::try_from(data.unit.width()).unwrap_or(1);
    let one = data.count == 1 && !data.unit.is_string();
    item(if a >= file_end {
        DataKind::Uninitialised {
            width: if one { width } else { 0 },
        }
    } else if data.unit.is_string() {
        DataKind::String {
            wide: data.unit == Unit::Utf16,
        }
    } else if one {
        DataKind::Scalar { width }
    } else {
        DataKind::Values { width }
    })
}

/// Bytes nothing typed at `a`, before `next`: `align` where zeros pad to
/// `next`'s alignment, runs of one value as `dup`, the rest one byte a
/// line.
fn unexplored(b: &Builder<'_, '_>, a: u64, next: u64) -> DataItem {
    let bytes = b.bytes(a, next - a);
    let Some(&first) = bytes.first() else {
        return DataItem {
            start: a,
            size: next - a,
            kind: DataKind::Fill { byte: 0 },
        };
    };
    let run = bytes.iter().take_while(|&&x| x == first).count() as u64;
    if first == 0
        && run == next - a
        && let Some(to) = alignment(a, next)
    {
        return DataItem {
            start: a,
            size: run,
            kind: DataKind::Align { to },
        };
    }
    if run > SHORT_RUN {
        return DataItem {
            start: a,
            size: run,
            kind: DataKind::Fill { byte: first },
        };
    }
    // Up to where a run starts.
    let size = (1..bytes.len())
        .find(|&i| {
            let tail = bytes.get(i..).unwrap_or_default();
            let x = tail.first().copied().unwrap_or(1);
            let n = tail.iter().take_while(|&&y| y == x).count() as u64;
            n > SHORT_RUN
        })
        .unwrap_or(bytes.len()) as u64;
    DataItem {
        start: a,
        size,
        kind: DataKind::Unexplored,
    }
}

/// The alignment padding from `a` to `next` makes (an `align` line): that
/// of `next` (its lowest set bit), at most [`MAX_ALIGN`], if the padding
/// is shorter.
pub(crate) fn alignment(a: u64, next: u64) -> Option<u64> {
    let to = (1u64 << next.trailing_zeros().min(63)).min(MAX_ALIGN);
    (to >= 2 && next > a && next - a < to).then_some(to)
}

/// The lines of `item`: one per piece, its cross-references after the
/// first (on lines of their own if the first reaches the comment
/// column, as data comments are placed), a pointed-to string's preview.
pub(crate) fn push(b: &mut Builder<'_, '_>, item: DataItem) {
    b.name_data(item);
    b.l.items.push(item);
    let kind = if item.kind == DataKind::Unexplored {
        Item::Unexplored
    } else {
        Item::Data
    };
    let data = b.bytes(item.start, item.size);
    let pieces = pieces(item, data, b.l.data_style(), b.l.quote());
    let xrefs = if matches!(item.kind, DataKind::Align { .. }) {
        0
    } else {
        b.xref_count(item.start, item.start + item.size)
    };
    let moved = xrefs > 0 && {
        let mut r = Rendered::default();
        b.l.render_data_body(data, &mut r, item, 0, 0);
        r.width() >= COMMENTS
    };
    if b.exported.contains(&item.start) {
        b.push(item.start, LineKind::Public, 0, kind);
    }
    b.push(
        item.start,
        LineKind::Data,
        if moved { MOVED } else { 0 },
        kind,
    );
    for k in u32::from(!moved)..xrefs {
        b.push(item.start, LineKind::Xref, k, kind);
    }
    for k in 1..pieces {
        b.push(item.start, LineKind::Data, k, kind);
    }
    if let DataKind::Pointer { target } = item.kind
        && b.strings.contains_key(&target)
    {
        b.push(item.start, LineKind::Preview, 0, kind);
    }
}

/// The flag of a data line whose comment is on the lines after it.
pub(crate) const MOVED: u32 = 1 << 31;

/// How many lines `item` takes.
fn pieces(item: DataItem, data: &[u8], style: Numbers, quote: char) -> u32 {
    let n = match item.kind {
        DataKind::String { wide } => string_pieces(data, wide, style, quote).len() as u64,
        DataKind::Table { width, .. } => item.size / u64::from(width.max(1)),
        DataKind::Values { width } => item
            .size
            .div_ceil(u64::from(per_line(width)) * u64::from(width)),
        DataKind::Unexplored => item.size,
        DataKind::Pointer { .. }
        | DataKind::Import { .. }
        | DataKind::Scalar { .. }
        | DataKind::Fill { .. }
        | DataKind::Uninitialised { .. }
        | DataKind::Align { .. } => 1,
    };
    u32::try_from(n.max(1)).unwrap_or(u32::MAX)
}

/// Values of `width` bytes on one line.
pub(crate) fn per_line(width: u8) -> u8 {
    (16 / width.max(1)).max(1)
}

/// A string's bytes in lines: a new line after each
/// newline, and before a unit that would take the line's operand (quotes
/// and commas included, other units as numbers in `style`) past
/// [`STRING_WRAP`] characters.
pub(crate) fn string_pieces(
    data: &[u8],
    wide: bool,
    style: Numbers,
    quote: char,
) -> Vec<(usize, usize)> {
    let unit = if wide { 2 } else { 1 };
    let mut pieces = Vec::new();
    let mut start = 0;
    let mut at = 0;
    // The operand's length so far, closing quote included, and whether
    // it ends in quoted text.
    let (mut length, mut quoted) = (0, false);
    while at < data.len() {
        let value = unit_value(data, at, wide);
        let printable = printable(value, quote);
        let comma = usize::from(length > 0);
        let added = match (printable, quoted) {
            (true, true) => 1,
            (true, false) => comma + 3,
            (false, _) => comma + number(u64::from(value), style).len(),
        };
        let newline = value == u32::from(b'\n');
        // A newline ends its line whatever the length.
        if length > 0 && length + added > STRING_WRAP && !newline {
            pieces.push((start, at));
            start = at;
            (length, quoted) = (0, false);
            continue;
        }
        length += added;
        quoted = printable;
        at += unit;
        // Not before the terminator alone (`db 0Ah,0`).
        if newline && data.len().saturating_sub(at) > unit {
            pieces.push((start, at));
            start = at;
            (length, quoted) = (0, false);
        }
    }
    if start < data.len() || pieces.is_empty() {
        pieces.push((start, data.len()));
    }
    pieces
}

/// Whether a string's unit `value` is written as text between `quote`s.
pub(crate) fn printable(value: u32, quote: char) -> bool {
    char::from_u32(value).is_some_and(|c| (c == ' ' || c.is_ascii_graphic()) && c != quote)
}

fn unit_value(data: &[u8], at: usize, wide: bool) -> u32 {
    let low = u32::from(data.get(at).copied().unwrap_or(0));
    if wide {
        low | (u32::from(data.get(at + 1).copied().unwrap_or(0)) << 8)
    } else {
        low
    }
}

impl Listing {
    /// Data line `k` of the item at `address`.
    pub(crate) fn render_data(
        &self,
        db: &Database<'_>,
        r: &mut Rendered,
        address: u64,
        aux: u32,
        base: usize,
    ) {
        let Some(&item) = self.item(address) else {
            return;
        };
        let k = aux & !MOVED;
        let data = bytes(db.image(), address, item.size);
        self.render_data_body(data, r, item, k, base);
        if aux == 0 {
            self.xref_comment(db, r, address, address + item.size, 0, base + COMMENTS);
        }
    }

    /// Line `k` of data item `item` of bytes `data`, without its comment.
    pub(super) fn render_data_body(
        &self,
        data: &[u8],
        r: &mut Rendered,
        item: DataItem,
        k: u32,
        base: usize,
    ) {
        let address = item.start;
        if k == 0
            && let Some(name) = self.names.get(&address)
        {
            r.tokens.push(name.token(address));
        }
        r.pad_to(base + MNEMONIC, true);
        let arm = self.decoder == Some(Decoder::Aarch64);
        match item.kind {
            DataKind::String { wide } => self.string_piece(r, data, wide, k, arm),
            DataKind::Pointer { target } => {
                Self::directive(r, u32::from(self.pointer_size), arm);
                if !arm {
                    r.push(Role::OperandKeyword, "offset ");
                }
                self.push_expr(r, target);
            }
            DataKind::Import { index } => {
                Self::directive(r, u32::try_from(item.size).unwrap_or(8), arm);
                if !arm {
                    r.push(Role::OperandKeyword, "offset ");
                }
                let name = self.imports.get(index as usize).map_or("?", String::as_str);
                r.push(Role::ImportName, name);
            }
            DataKind::Scalar { width } => {
                Self::directive(r, u32::from(width), arm);
                let value = read(data, 0, width);
                let named = !self.relocatable
                    && width == self.pointer_size
                    && self.section_of(value).is_some();
                if named && self.names.contains_key(&value) {
                    if !arm {
                        r.push(Role::OperandKeyword, "offset ");
                    }
                    self.push_expr(r, value);
                } else {
                    r.push(Role::Number, self.data_number(value));
                }
            }
            DataKind::Values { width } => {
                Self::directive(r, u32::from(width), arm);
                let per = u64::from(per_line(width)) * u64::from(width);
                let from = u64::from(k) * per;
                let values: Vec<u64> = (from..(from + per).min(item.size))
                    .step_by(usize::from(width))
                    .map(|o| read(data, o, width))
                    .collect();
                self.value_list(r, &values);
            }
            DataKind::Fill { byte } => {
                Self::directive(r, 1, arm);
                self.dup(r, item.size, Some(u64::from(byte)));
            }
            DataKind::Uninitialised { width } => {
                if width > 0 {
                    Self::directive(r, u32::from(width), arm);
                    r.push(Role::Punctuation, "?");
                } else {
                    Self::directive(r, 1, arm);
                    self.dup(r, item.size, None);
                }
            }
            DataKind::Align { to } => {
                r.push(Role::PaddingMnemonic, if arm { "ALIGN " } else { "align " });
                r.push(Role::Number, self.data_number(to));
            }
            DataKind::Table { width, relative } => {
                Self::directive(r, u32::from(width), arm);
                let entry = read(data, u64::from(k) * u64::from(width), width);
                let target = if relative {
                    let offset = i64::from(u32::try_from(entry).map_or(0, u32::cast_signed));
                    address.wrapping_add_signed(offset)
                } else {
                    entry
                };
                r.push(Role::OperandKeyword, "offset ");
                self.push_expr(r, target);
                if relative {
                    r.push(Role::Punctuation, " - ");
                    r.push(Role::Number, self.data_number(address));
                }
            }
            DataKind::Unexplored => {
                r.push(Role::Keyword, if arm { "DCB" } else { "db" });
                let value = self.data_number(u64::from(data.get(k as usize).copied().unwrap_or(0)));
                r.push(
                    Role::Space,
                    " ".repeat(5usize.saturating_sub(value.len()).max(1)),
                );
                r.push(Role::Number, value);
            }
        }
    }

    fn data_number(&self, value: u64) -> String {
        number(value, self.data_style())
    }

    /// How data numbers are written: AArch64's always as C's.
    pub(crate) fn data_style(&self) -> Numbers {
        if self.decoder == Some(Decoder::Aarch64) {
            Numbers::C
        } else {
            self.options.numbers
        }
    }

    /// The quote around strings' text: `'` for x86, AArch64 assemblers' `"`.
    pub(crate) fn quote(&self) -> char {
        if self.decoder == Some(Decoder::Aarch64) {
            '"'
        } else {
            '\''
        }
    }

    /// `db`…`dq`, `xmmword` (AArch64: `DCB`…`DCQ`), and a space.
    fn directive(r: &mut Rendered, width: u32, arm: bool) {
        let word = match (width, arm) {
            (2, false) => "dw",
            (4, false) => "dd",
            (8, false) => "dq",
            (10, false) => "dt",
            (16, false) => "xmmword",
            (2, true) => "DCW",
            (4, true) => "DCD",
            (8, true) => "DCQ",
            (_, false) => "db",
            (_, true) => "DCB",
        };
        r.push(Role::Keyword, word);
        r.push(Role::Space, " ");
    }

    /// `N dup(v)`, `N dup(?)`.
    fn dup(&self, r: &mut Rendered, count: u64, value: Option<u64>) {
        r.push(Role::Number, self.data_number(count));
        r.push(Role::Keyword, " dup");
        r.push(Role::Punctuation, "(");
        match value {
            Some(v) => r.push(Role::Number, self.data_number(v)),
            None => r.push(Role::Punctuation, "?"),
        }
        r.push(Role::Punctuation, ")");
    }

    /// Values separated by commas, runs of one value as `N dup(v)`.
    fn value_list(&self, r: &mut Rendered, values: &[u64]) {
        let mut i = 0;
        while let Some(&v) = values.get(i) {
            if i > 0 {
                r.push(Role::Punctuation, ", ");
            }
            let run = values
                .get(i..)
                .unwrap_or_default()
                .iter()
                .take_while(|&&x| x == v)
                .count();
            if run as u64 > SHORT_RUN - 1 {
                self.dup(r, run as u64, Some(v));
                i += run;
            } else {
                r.push(Role::Number, self.data_number(v));
                i += 1;
            }
        }
    }

    /// Piece `k` of a string: printable runs quoted, other units as
    /// numbers, the NUL at the end (`'rbash',0`; UTF-16 after
    /// `text "UTF-16LE",`).
    fn string_piece(&self, r: &mut Rendered, data: &[u8], wide: bool, k: u32, arm: bool) {
        let quote = self.quote();
        let pieces = string_pieces(data, wide, self.data_style(), quote);
        let Some(&(start, end)) = pieces.get(k as usize) else {
            return;
        };
        if wide {
            r.push(Role::Keyword, "text ");
            r.push(Role::String, "\"UTF-16LE\"");
            r.push(Role::Punctuation, ", ");
        } else {
            r.push(Role::Keyword, if arm { "DCB" } else { "db" });
            r.push(Role::Space, " ");
        }
        let unit = if wide { 2 } else { 1 };
        let mut quoted = String::new();
        let mut first = true;
        let flush = |r: &mut Rendered, quoted: &mut String, first: &mut bool| {
            if !quoted.is_empty() {
                if !*first {
                    r.push(Role::Punctuation, ",");
                }
                r.push(Role::String, format!("{quote}{quoted}{quote}"));
                quoted.clear();
                *first = false;
            }
        };
        let mut at = start;
        while at < end {
            let value = unit_value(data, at, wide);
            at += unit;
            if let Some(c) = char::from_u32(value).filter(|_| printable(value, quote)) {
                quoted.push(c);
            } else {
                flush(r, &mut quoted, &mut first);
                if !first {
                    r.push(Role::Punctuation, ",");
                }
                r.push(Role::Number, self.data_number(u64::from(value)));
                first = false;
            }
        }
        flush(r, &mut quoted, &mut first);
    }
}

/// Whether reference kind `kind` comes from code (a `CODE XREF`).
pub(crate) fn is_code_kind(kind: Kind) -> bool {
    matches!(kind, Kind::Call | Kind::Jump)
}

#[cfg(test)]
mod tests {
    use super::{alignment, string_pieces};
    use crate::listing::Numbers;

    #[test]
    fn padding_aligns_to_the_next_items_alignment() {
        assert_eq!(alignment(0x0011_EA48, 0x0011_EA50), Some(0x10));
        // The next item's alignment, at most 32.
        assert_eq!(alignment(0x1DCF2, 0x1DD00), Some(0x20));
        assert_eq!(alignment(0x1ECEF, 0x1ECF0), Some(0x10));
        assert_eq!(alignment(0x1001, 0x1004), Some(4));
        // Not a padding: the next item is not aligned to what it would take.
        assert_eq!(alignment(0x1000, 0x1008), None);
    }

    #[test]
    fn strings_break_after_newlines_and_at_the_margin() {
        let pieces = |data: &[u8], wide| string_pieces(data, wide, Numbers::Masm, '\'');
        // The terminator stays with the last newline (`db 0Ah,0`).
        assert_eq!(pieces(b"ab\ncd\n\0", false), [(0, 3), (3, 7)]);
        assert_eq!(pieces(b"ab\n\n\0", false), [(0, 3), (3, 5)]);
        // 65 characters and their quotes make 67.
        assert_eq!(pieces(&[b'x'; 70], false), [(0, 65), (65, 70)]);
        assert_eq!(pieces(&[b'x'; 65], false), [(0, 65)]);
        // Units written as numbers count as their text and a comma:
        // `'x',27h,` … eight pairs and an `'x'` make 67.
        let quotes: Vec<u8> = b"x'".repeat(10);
        assert_eq!(pieces(&quotes, false), [(0, 17), (17, 20)]);
        let wide = [b'a', 0, b'\n', 0, b'b', 0, 0, 0];
        assert_eq!(pieces(&wide, true), [(0, 4), (4, 8)]);
    }
}
