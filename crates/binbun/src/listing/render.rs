//! A line's tokens: the prefix, then what the line is.

use std::fmt::Write as _;

use binbun_loader::Image;

use crate::Database;
use crate::listing::data::{MOVED, is_code_kind, per_line, string_pieces};
use crate::listing::names::dummy;
use crate::listing::text::{COMMENTS, MNEMONIC, PREVIEW, number, preview, signed, size_word};
use crate::listing::{DataKind, LineKind, Listing, Rendered, Role, Row, Token};
use crate::references::{Kind, Reference};

/// The width of border lines after `; `.
const BORDER: usize = 75;

/// Up to `len` bytes the file supplies at `address`.
pub(crate) fn bytes<'a>(image: &Image<'a>, address: u64, len: u64) -> &'a [u8] {
    let Some(segment) = image.segment(address) else {
        return &[];
    };
    let bytes: &'a [u8] = segment.bytes;
    let Ok(offset) = usize::try_from(address - segment.start) else {
        return &[];
    };
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    bytes
        .get(offset..)
        .map_or(&[], |b| b.get(..len.min(b.len())).unwrap_or_default())
}

/// The little-endian value of `width` bytes at `offset` of `data`.
pub(crate) fn read(data: &[u8], offset: u64, width: u8) -> u64 {
    let mut v = [0u8; 8];
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let part = data.get(start..).unwrap_or_default();
    for (d, s) in v
        .iter_mut()
        .zip(part.iter().take(usize::from(width.min(8))))
    {
        *d = *s;
    }
    u64::from_le_bytes(v)
}

/// One cross-reference line: the reference shown (none: only `...`),
/// whether it starts its kind (`CODE XREF: `), whether `...` follows.
#[derive(Clone, Copy, Debug)]
pub(crate) struct XrefLine<'a> {
    reference: Option<&'a Reference>,
    first: bool,
    code: bool,
    more: bool,
}

/// The cross-reference lines of `refs` with `shown` at most: code ones
/// first, each kind by where it is made; `...` after the last shown of a
/// kind that has more; a kind with none shown but some made is one
/// `DATA XREF: ...` line.
pub(crate) fn xref_layout(refs: &[Reference], shown: usize) -> Vec<XrefLine<'_>> {
    if shown == 0 {
        return Vec::new();
    }
    let mut code: Vec<&Reference> = refs.iter().filter(|r| is_code_kind(r.kind)).collect();
    let mut data: Vec<&Reference> = refs.iter().filter(|r| !is_code_kind(r.kind)).collect();
    // One per place it is made: the last kind (a write over a read, an
    // address taken over both, as the instruction's operand says).
    for group in [&mut code, &mut data] {
        group.sort_by_key(|r| (r.from, std::cmp::Reverse(r.kind)));
        group.dedup_by_key(|r| r.from);
    }
    let mut lines = Vec::new();
    let mut room = shown;
    for (group, is_code) in [(code, true), (data, false)] {
        if group.is_empty() {
            continue;
        }
        let n = group.len().min(room);
        room -= n;
        if n == 0 {
            lines.push(XrefLine {
                reference: None,
                first: true,
                code: is_code,
                more: true,
            });
            continue;
        }
        for (i, &r) in group.iter().take(n).enumerate() {
            lines.push(XrefLine {
                reference: Some(r),
                first: i == 0,
                code: is_code,
                more: i + 1 == n && group.len() > n,
            });
        }
    }
    lines
}

impl Listing {
    pub(super) fn render_row(&self, db: &Database<'_>, row: Row, r: &mut Rendered) {
        let address = self.piece_address(db, row);
        let section = self.section_of(address).map_or("?", |s| s.name.as_str());
        r.push_target(
            Role::Prefix,
            format!("{section}:{address:0w$X}", w = self.digits),
            address,
        );
        if matches!(row.kind, LineKind::Blank | LineKind::Comment) {
            return;
        }
        r.push(Role::Space, " ");
        if self.options.opcode_bytes > 0 {
            let field = self.options.opcode_bytes * 3 + 1;
            let start = r.width();
            if row.kind == LineKind::Instruction {
                let shown = bytes(db.image(), row.address, u64::from(row.aux));
                let mut text = String::new();
                for (i, b) in shown.iter().take(self.options.opcode_bytes).enumerate() {
                    if i > 0 {
                        text.push(' ');
                    }
                    let _ = write!(text, "{b:02X}");
                }
                if shown.len() > self.options.opcode_bytes {
                    text.push('+');
                }
                r.push(Role::OpcodeBytes, text);
            }
            r.pad_to(start + field, false);
        }
        let base = r.width();
        self.render_kind(db, row, r, base);
    }

    /// The address of the bytes a data line shows: its piece's (a
    /// string's line, a table's entry), else the item's.
    fn piece_address(&self, db: &Database<'_>, row: Row) -> u64 {
        let k = row.aux & !MOVED;
        if row.kind != LineKind::Data || k == 0 {
            return row.address;
        }
        let Some(item) = self.item(row.address) else {
            return row.address;
        };
        let offset = match item.kind {
            DataKind::String { wide } => {
                let data = bytes(db.image(), item.start, item.size);
                string_pieces(data, wide, self.data_style(), self.quote())
                    .get(k as usize)
                    .map_or(0, |&(start, _)| start as u64)
            }
            DataKind::Table { width, .. } => u64::from(k) * u64::from(width),
            DataKind::Values { width } => {
                u64::from(k) * u64::from(per_line(width)) * u64::from(width)
            }
            DataKind::Unexplored => u64::from(k),
            DataKind::Pointer { .. }
            | DataKind::Import { .. }
            | DataKind::Scalar { .. }
            | DataKind::Fill { .. }
            | DataKind::Uninitialised { .. }
            | DataKind::Align { .. } => 0,
        };
        row.address + offset
    }

    fn render_kind(&self, db: &Database<'_>, row: Row, r: &mut Rendered, base: usize) {
        let auto = |r: &mut Rendered, text: String| r.push(Role::AutoComment, text);
        match row.kind {
            LineKind::Blank | LineKind::Comment => {}
            LineKind::SegmentBorder => auto(r, format!("; {}", "=".repeat(BORDER))),
            LineKind::SegmentType => {
                let kind = self.section_of(row.address).map_or("Pure data", |s| {
                    if s.code {
                        "Pure code"
                    } else if s.file_end == s.start {
                        "Uninitialized"
                    } else {
                        "Pure data"
                    }
                });
                auto(r, format!("; Segment type: {kind}"));
            }
            LineKind::SegmentPermissions => {
                let words = self
                    .section_of(row.address)
                    .map_or("", |s| s.permissions.as_str());
                auto(r, format!("; Segment permissions: {words}"));
            }
            LineKind::Banner => {
                let head = "; =============== S U B R O U T I N E ";
                auto(r, format!("{head}{}", "=".repeat(BORDER + 2 - head.len())));
            }
            LineKind::Attributes => {
                let f = self.functions.get(&row.address);
                let words: Vec<&str> = [
                    (f.is_some_and(|f| f.noreturn), "noreturn"),
                    (f.is_some_and(|f| f.bp_frame), "bp-based frame"),
                ]
                .into_iter()
                .filter_map(|(on, word)| on.then_some(word))
                .collect();
                auto(r, format!("; Attributes: {}", words.join(" ")));
            }
            LineKind::Prototype => {
                let text = self
                    .functions
                    .get(&row.address)
                    .and_then(|f| f.prototype.as_deref())
                    .unwrap_or("");
                r.push(Role::Comment, format!("; {text}"));
            }
            LineKind::Public => {
                r.pad_to(base + MNEMONIC, false);
                r.push(Role::Directive, "public ");
                self.push_name(r, row.address);
            }
            LineKind::Proc => {
                self.push_name(r, row.address);
                r.pad_to(base + MNEMONIC, true);
                r.push(Role::Directive, "proc near");
                self.xref_comment(db, r, row.address, row.address + 1, 0, base + COMMENTS);
            }
            LineKind::End => {
                if let Some((_, entry)) = self.function_of(row.address) {
                    self.push_name(r, entry);
                }
                r.pad_to(base + MNEMONIC, true);
                r.push(Role::Directive, "endp");
            }
            LineKind::Frame => self.render_frame(r, row, base),
            LineKind::Label => {
                self.push_name(r, row.address);
                r.push(Role::Punctuation, ":");
                self.xref_comment(db, r, row.address, row.address + 1, 0, base + COMMENTS);
            }
            LineKind::Xref => {
                let end = self
                    .item(row.address)
                    .map_or(row.address + 1, |item| item.start + item.size);
                self.xref_comment(db, r, row.address, end, row.aux as usize, base + COMMENTS);
            }
            LineKind::Preview => {
                r.pad_to(base + COMMENTS, false);
                if let Some(item) = self.item(row.address)
                    && let DataKind::Pointer { target } = item.kind
                    && let Some(text) = self.strings.get(&target)
                {
                    auto(r, format!("; {}", preview(text, PREVIEW)));
                }
            }
            LineKind::Instruction => self.render_instruction(db, r, row.address, row.aux, base),
            LineKind::Data => self.render_data(db, r, row.address, row.aux, base),
            LineKind::Separator => auto(r, format!("; {}", "-".repeat(BORDER))),
        }
    }

    /// `var_54          = dword ptr -54h`.
    fn render_frame(&self, r: &mut Rendered, row: Row, base: usize) {
        let Some(slot) = self
            .functions
            .get(&row.address)
            .and_then(|f| f.frame.get(row.aux as usize))
        else {
            return;
        };
        r.push_local(slot_name(slot.offset));
        r.pad_to(base + MNEMONIC, true);
        r.push(Role::Punctuation, "=");
        r.push(Role::Space, " ");
        r.push(
            Role::OperandKeyword,
            format!("{} ptr", size_word(slot.size)),
        );
        r.push(Role::Space, " ");
        if slot.offset >= 0 {
            r.push(Role::Space, " ");
        }
        r.push(Role::Number, signed(slot.offset, self.options.numbers));
    }

    /// The name of `address` as a token, in its kind's role.
    pub(crate) fn push_name(&self, r: &mut Rendered, address: u64) {
        r.tokens.push(match self.names.get(&address) {
            Some(name) => name.token(address),
            None => Token {
                text: dummy("loc", address),
                role: Role::CodeName,
                target: Some(address),
                automatic: true,
            },
        });
    }

    /// `address` as a name expression: its name, else the name of the
    /// item or function holding it plus the offset, else a dummy name;
    /// never a name plus an offset past the named item. A token going to
    /// `address`, automatic if its name is.
    pub(crate) fn expr(&self, address: u64) -> Token {
        if let Some(name) = self.names.get(&address) {
            return name.token(address);
        }
        let style = self.options.numbers;
        if let Some(item) = self.item_holding(address)
            && let Some(name) = self.names.get(&item.start)
        {
            return Token {
                text: format!("{}+{}", name.text, number(address - item.start, style)),
                role: name.kind.role(),
                target: Some(address),
                automatic: name.automatic,
            };
        }
        // Code is named where it is referred to (a label), never as its
        // function plus an offset.
        let in_code = self.section_of(address).is_some_and(|s| s.code);
        let (text, role) = if in_code {
            (dummy("loc", address), Role::CodeName)
        } else {
            (dummy("unk", address), Role::DataName)
        };
        Token {
            text,
            role,
            target: Some(address),
            automatic: true,
        }
    }

    /// Pushes [`Self::expr`] of `address`.
    pub(crate) fn push_expr(&self, r: &mut Rendered, address: u64) {
        r.tokens.push(self.expr(address));
    }

    /// Cross-reference line `k` of the item `start..end`, at `column`.
    pub(crate) fn xref_comment(
        &self,
        db: &Database<'_>,
        r: &mut Rendered,
        start: u64,
        end: u64,
        k: usize,
        column: usize,
    ) {
        let refs = db.references().within(start..end.max(start + 1));
        let layout = xref_layout(refs, self.options.xrefs);
        let Some(line) = layout.get(k) else {
            return;
        };
        r.pad_to(column, true);
        let role = if line.code {
            Role::CodeXref
        } else {
            Role::DataXref
        };
        let mut text = String::from("; ");
        if line.first {
            text.push_str(if line.code {
                "CODE XREF: "
            } else {
                "DATA XREF: "
            });
        }
        let Some(reference) = line.reference else {
            text.push_str("...");
            r.push(role, text);
            return;
        };
        r.push(role, text);
        let arrow = if reference.from < reference.target {
            '↑'
        } else {
            '↓'
        };
        let letter = match reference.kind {
            Kind::Call => 'p',
            Kind::Jump => 'j',
            Kind::Read => 'r',
            Kind::Write => 'w',
            Kind::Address | Kind::Pointer(_) => 'o',
        };
        r.push_target(role, self.xref_source(reference.from), reference.from);
        r.push(
            role,
            format!("{arrow}{letter}{}", if line.more { " ..." } else { "" }),
        );
    }

    /// Where a reference is made, as a cross-reference writes it: `main+58`,
    /// `.data.rel.ro:readarray_doc`, `LOAD:7850`.
    fn xref_source(&self, from: u64) -> String {
        if let Some((_, entry)) = self.function_of(from) {
            if from != entry
                && let Some(label) = self.names.get(&from)
            {
                let function = self.names.get(&entry).map_or("?", |n| n.text.as_str());
                return format!("{function}:{}", label.text);
            }
            return self.describe(from);
        }
        let section = self.section_of(from).map_or("?", |s| s.name.as_str());
        if let Some(item) = self.item_holding(from)
            && let Some(name) = self.names.get(&item.start)
        {
            return if from == item.start {
                format!("{section}:{}", name.text)
            } else {
                format!("{section}:{}+{:X}", name.text, from - item.start)
            };
        }
        format!("{section}:{from:0w$X}", w = self.digits)
    }
}

/// The name of the frame slot at `offset` from `rbp`: `var_54` below
/// it, `arg_0` from the first stack argument (16 above it) up.
pub(crate) fn slot_name(offset: i64) -> String {
    if offset < 0 {
        format!("var_{:X}", offset.unsigned_abs())
    } else {
        format!("arg_{:X}", offset.unsigned_abs().saturating_sub(16))
    }
}

/// The offset from `rbp` of the frame slot [`slot_name`] names `name`.
pub(crate) fn slot_offset(name: &str) -> Option<i64> {
    let (negative, digits) = match (name.strip_prefix("var_"), name.strip_prefix("arg_")) {
        (Some(digits), _) => (true, digits),
        (None, Some(digits)) => (false, digits),
        (None, None) => return None,
    };
    if digits.is_empty()
        || !digits
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase())
    {
        return None;
    }
    let magnitude = i64::from_str_radix(digits, 16).ok()?;
    if negative {
        (magnitude > 0).then_some(-magnitude)
    } else {
        magnitude.checked_add(16)
    }
}

#[cfg(test)]
mod tests {
    use super::{slot_name, slot_offset};

    #[test]
    fn a_slot_name_reads_back_as_its_offset_and_nothing_else_does() {
        for offset in [-0x54, -8, -1, 16, 0x28] {
            assert_eq!(slot_offset(&slot_name(offset)), Some(offset), "{offset}");
        }
        for name in ["var_0", "var_1f", "var_", "arg_G", "loc_10", "var_-8"] {
            assert_eq!(slot_offset(name), None, "{name}");
        }
    }
}
