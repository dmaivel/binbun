//! The unified listing's rows as shown: each built once into a
//! [`RowView`], what its columns say, which the pane draws and Copy
//! writes. A row's view comes from what [`RowsCtx`] gathers once (a
//! frame, a Copy): the document and its sources, the session's database
//! and file, the columns, the C's link, the highlighted token, the
//! comment field.

use std::fmt::Write as _;
use std::ops::Range;
use std::sync::Arc;

use binbun::Database;
use binbun_gui_view::View;
use binbun_gui_view::cdoc::CDocument;
use binbun_gui_view::hex::{Kind, Mode, Overlay, Source};
use binbun_gui_view::hex_tree::{self, Key};
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::listing::{LineKind, Overlay as ListingOverlay, Role, Token};
use binbun_gui_view::session::Session;
use binbun_gui_view::unified::{ItemKind, Piece, Row, RowKind};

use crate::comment_field::CommentEdit;
use crate::hex_view::kind_color;
use crate::highlight::Highlight;
use crate::listing_view::{column, tones};
use crate::search_view::FindKind;
use crate::theme::dim;
use crate::unified_view::{
    BYTES_SHOWN, Columns, FIELD_NAME_MOST, FIELD_TYPE_MOST, Part, Sources, XrefChip, size_text,
    xref_chips,
};
use crate::workspace::{Link, Workspace, f};

/// What header a row is, drawn over the branch arrows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Header {
    /// None: a line, a tree row, bytes.
    None,
    /// An item's card (a section's, a header's).
    Item,
    /// A piece's card (a function's, a global's, untyped bytes').
    Piece,
    /// A labelled block's header.
    Block,
}

/// A row as shown: what each of its columns says, and how it is marked.
pub struct RowView<'a> {
    /// The address column (the address, else the file offset), and its
    /// colour.
    pub place: (String, u32),
    /// The bytes column.
    pub bytes: Option<Vec<Part>>,
    /// The find bar's byte matches in the bytes column, by its text's
    /// bytes.
    pub byte_marks: Vec<(Range<usize>, u32)>,
    /// Where the text starts (the pane's pixels).
    pub start: f32,
    /// The text.
    pub parts: Vec<Part>,
    /// The parts lit as the highlighted token's equals.
    pub lit: Vec<usize>,
    /// The find bar's matches, by the text's bytes.
    pub marks: Vec<(Range<usize>, u32)>,
    /// What it says at its right edge (a size, an offset).
    pub meta: Option<String>,
    /// A card's or a block's chevron in the fold column (whether open).
    pub fold: Option<bool>,
    /// A tree row's chevron, left of its name.
    pub inline_fold: Option<bool>,
    /// What header it is.
    pub header: Header,
    /// A block's header heading a loop.
    pub loop_head: bool,
    /// Its item's cross-references, one badge.
    pub xrefs: Option<Vec<XrefChip>>,
    /// The C a block starts with, after its badge.
    pub snippet: Vec<Part>,
    /// Its bytes' kind: the stripe at its left edge.
    pub kind: Option<Kind>,
    /// The C's link: the wash of an instruction its hovered token or its
    /// cursor stands on, the tint of its line.
    pub linked_wash: Option<u32>,
    pub tint: Option<u32>,
    /// A section card's strip: what the section holds where.
    pub strip: Option<&'a [Kind]>,
    /// Where (characters from `start`) a Set type field opens over its
    /// type, and the comment field (the line it is open on).
    pub type_column: Option<usize>,
    pub comment_column: Option<usize>,
}

/// What a pane's rows are built from, gathered once.
pub struct RowsCtx<'a> {
    pub id: PaneId,
    pub sources: &'a Sources,
    pub session: &'a Session,
    pub db: &'a Database<'a>,
    pub file: &'a [u8],
    pub overlay: &'a ListingOverlay,
    pub cols: Columns,
    /// The address column's width in digits.
    pub digits: usize,
    /// The C view a function's printed C is read from.
    pub view: View,
    /// The linked C (a synced pane's), the instructions behind its cursor
    /// or selection, its hovered token's.
    pub linked: Option<Arc<CDocument>>,
    pub behind: Vec<u64>,
    pub hovered: &'a [u64],
    /// The highlighted token's text (a click on a name, a register).
    pub highlight: Option<&'a str>,
    /// The comment field: its edit, the line its item's comment starts
    /// on, the column there.
    pub field: Option<(&'a CommentEdit, u64, usize)>,
}

impl<'a> RowsCtx<'a> {
    /// The file's byte at offset `at`.
    fn byte_at(&self, at: u64) -> Option<u8> {
        usize::try_from(at)
            .ok()
            .and_then(|i| self.file.get(i))
            .copied()
    }

    /// The kinds of `len` bytes from a row's place (its address, else its
    /// file offset).
    fn kinds(&self, address: Option<u64>, offset: Option<u64>, len: u64) -> Vec<Kind> {
        let (_, listing, image, _) = self.sources;
        let (mode, at) = match (address, offset) {
            (Some(a), _) => (Mode::Address, a),
            (None, Some(o)) => (Mode::File, o),
            (None, None) => return Vec::new(),
        };
        image
            .cells(self.file, Some(listing.lines()), mode, at..at + len.max(1))
            .into_iter()
            .map(|c| c.kind)
            .collect()
    }

    /// Up to [`BYTES_SHOWN`] of `len` bytes from a row's place, as hex
    /// (`+` where there are more; none for addresses the file leaves
    /// out).
    fn hex_of(&self, address: Option<u64>, offset: Option<u64>, len: u64) -> String {
        let (_, _, image, _) = self.sources;
        let at = offset.or_else(|| image.to_file(address?));
        let mut text = String::new();
        let shown = len.min(BYTES_SHOWN as u64);
        for i in 0..shown {
            if let Some(b) = at.and_then(|o| self.byte_at(o + i)) {
                let _ = write!(text, "{b:02X} ");
            }
        }
        if len > shown && !text.is_empty() {
            text.pop();
            text.push('+');
        }
        text
    }

    /// The name the listing shows for `address`.
    fn name(&self, address: u64) -> Option<String> {
        self.sources
            .1
            .shown_name(address, self.overlay)
            .map(str::to_owned)
    }

    /// Tree row `key` as the table shows it.
    fn tree_row(&self, key: &Key) -> Option<hex_tree::Row> {
        let (_, _, image, overlays) = self.sources;
        let read = |overlay: &Overlay, range: Range<u64>| -> Vec<u8> {
            let (space, base) = overlay.anchor.place();
            image.read(self.file, space, base + range.start..base + range.end)
        };
        hex_tree::row(overlays, key, &read, image.little(), &|a| self.name(a))
    }

    /// The printed C of the function holding `address`, if printed (the
    /// unified listing asks for none).
    fn c_of(&self, address: u64) -> Option<&'a Arc<CDocument>> {
        let (function, _) = self.sources.1.function_of(address)?;
        self.session.document(function, self.view)
    }
}

/// Row view `v` as Copy writes it: its columns at their places in
/// characters (the address, the bytes, the text where it starts), then
/// the C a block starts with.
pub fn row_text(v: &RowView<'_>, cols: &Columns) -> String {
    let at = |x: f32| column(x - cols.address, cols.cw);
    let mut line = v.place.0.clone();
    let pad_to = |line: &mut String, to: usize| {
        let width = line.chars().count();
        let gap = if width + 2 > to { 2 } else { to - width };
        line.push_str(&" ".repeat(gap));
    };
    if let Some(bytes) = &v.bytes {
        pad_to(&mut line, at(cols.bytes));
        line.extend(bytes.iter().map(|p| p.0.as_str()));
    }
    let text: String = v.parts.iter().map(|p| p.0.as_str()).collect();
    if !text.trim().is_empty() {
        pad_to(&mut line, at(v.start));
        line.push_str(&text);
    }
    if !v.snippet.is_empty() {
        line.push_str("  ");
        line.extend(v.snippet.iter().map(|p| p.0.as_str()));
    }
    line.truncate(line.trim_end().len());
    line
}

impl Workspace {
    /// What pane `id`'s rows are built from now, of `sources`.
    pub fn rows_ctx<'a>(&'a self, id: PaneId, sources: &'a Sources) -> Option<RowsCtx<'a>> {
        let session = self.session.as_ref()?;
        let db = session.database()?;
        let (file, _) = session.loaded()?;
        let (_, listing, image, _) = sources;
        let state = self.panes.get(&id)?;
        let synced = self.layout.pane(id).is_some_and(|p| p.synced);
        let overlay = session.overlay();
        let field = self
            .comment
            .as_ref()
            .filter(|c| c.pane == id)
            .and_then(|c| {
                let n = listing.line_of(c.field.address);
                let (_, line, column) = listing.comment_place(db, n, overlay)?;
                Some((c, line, column))
            });
        Some(RowsCtx {
            id,
            sources,
            session,
            db,
            file,
            overlay,
            cols: self.unified_columns(id, sources),
            digits: image
                .prefix_width(Mode::Address)
                .max(image.prefix_width(Mode::File)),
            view: self.default_view(),
            linked: self.linked_document().filter(|_| synced),
            behind: if synced { self.behind_c() } else { Vec::new() },
            hovered: match &self.link {
                Some(Link::C { addresses, .. }) => addresses,
                Some(Link::Listing(_)) | None => &[],
            },
            highlight: state.listing.highlight.as_deref(),
            field,
        })
    }

    /// Row `row` as shown; `None` for one whose item or line is gone.
    pub fn row_view<'a>(&self, cx: &RowsCtx<'a>, row: &Row) -> Option<RowView<'a>> {
        let theme = self.theme;
        let (doc, listing, image, overlays) = cx.sources;
        let address = doc.address(row, listing, image, overlays);
        let file_at = doc.offset(row, image, overlays);
        let digits = cx.digits;
        let quiet = theme.text_placeholder;
        let place = match (address, file_at) {
            (Some(a), _) => (format!("{a:0digits$X}"), theme.line_number),
            (None, Some(o)) => (format!("{o:0digits$X}"), quiet),
            (None, None) => (String::new(), quiet),
        };
        let mut v = RowView {
            place,
            bytes: None,
            byte_marks: Vec::new(),
            start: cx.cols.text,
            parts: Vec::new(),
            lit: Vec::new(),
            marks: Vec::new(),
            meta: None,
            fold: None,
            inline_fold: None,
            header: Header::None,
            loop_head: false,
            xrefs: None,
            snippet: Vec::new(),
            kind: None,
            linked_wash: None,
            tint: None,
            strip: None,
            type_column: None,
            comment_column: None,
        };
        match &row.kind {
            RowKind::Card { item, piece, open } => {
                v.fold = Some(*open);
                self.card_view(cx, &mut v, *item, *piece)?;
            }
            RowKind::Block { line, open } => {
                v.fold = Some(*open);
                self.block_view(cx, &mut v, *line)?;
            }
            RowKind::Line(n) => self.line_view(cx, &mut v, *n)?,
            RowKind::Field(line) => {
                v.inline_fold = line.expandable.then_some(line.expanded);
                v.kind = cx.kinds(address, file_at, 1).first().copied();
                v.start = cx.cols.text + f(u64::from(row.depth.saturating_sub(1)) * 2) * cx.cols.cw;
                self.field_view(cx, &mut v, &line.key, (address, file_at));
            }
            RowKind::Hex(range) => self.hex_row_view(cx, &mut v, range, (address, file_at)),
            RowKind::Run { file, byte } => {
                v.start = cx.cols.bytes;
                let text = format!("{byte:02X} × {}", file.end - file.start);
                v.parts.push((text, theme.text_muted, false));
            }
            RowKind::Bytes(file) => {
                v.start = cx.cols.bytes;
                v.parts
                    .push(("Untyped bytes".to_owned(), theme.text_muted, false));
                v.meta = Some(size_text(file.end - file.start));
            }
            RowKind::Uninitialised(range) => {
                v.start = cx.cols.bytes;
                let text = format!("?? × {}", range.end - range.start);
                v.parts.push((text, theme.text_muted, false));
            }
            RowKind::Spacer => {}
        }
        Some(v)
    }

    /// An item's card (`piece` none) or a piece's: a section's, a
    /// header's, a function's (its decompiler signature where printed C
    /// says it), a global's, untyped bytes'.
    fn card_view<'a>(
        &self,
        cx: &RowsCtx<'a>,
        v: &mut RowView<'a>,
        item: usize,
        piece: Option<usize>,
    ) -> Option<()> {
        let theme = self.theme;
        let (doc, listing, ..) = cx.sources;
        let (muted, cw) = (theme.text_muted, cx.cols.cw);
        let it = doc.items.get(item)?;
        match piece.and_then(|p| it.pieces.get(p)) {
            None => {
                v.header = Header::Item;
                v.start = cx.cols.bytes;
                let (symbol, title, ty) = match &it.kind {
                    ItemKind::Header(key) => (
                        "≡",
                        it.name.clone(),
                        cx.tree_row(key).map(|r| r.ty).unwrap_or_default(),
                    ),
                    ItemKind::Section(kind) => ("§", it.name.clone(), section_title(*kind)),
                    ItemKind::Outside => ("·", "Outside sections".to_owned(), String::new()),
                };
                v.parts.push((format!("{symbol} "), muted, false));
                v.parts.push((title, theme.text, true));
                if !ty.is_empty() {
                    v.parts.push((format!("  {ty}"), muted, false));
                }
                v.strip = Some(it.strip.as_slice()).filter(|s| !s.is_empty());
                let size = match &it.address {
                    Some(a) if it.file.is_empty() => a.end - a.start,
                    Some(_) | None => it.file.end - it.file.start,
                };
                let mapped = if it.address.is_none() {
                    "not mapped · "
                } else {
                    ""
                };
                v.meta = Some(format!("{mapped}{}", size_text(size)));
            }
            Some(Piece::Function {
                entry,
                start: from,
                end: to,
                ..
            }) => {
                v.header = Header::Piece;
                v.kind = Some(Kind::Code);
                // A function's header on the left, under its section's.
                v.start = cx.cols.bytes + 2.0 * cw;
                v.parts.push(("ƒ ".to_owned(), theme.function, true));
                let function = || cx.name(*entry).unwrap_or_else(|| format!("sub_{entry:X}"));
                if from == entry {
                    match self.unified_signature(*entry, cx.c_of(*entry)) {
                        Some(signature) => v.parts.extend(signature),
                        None => v.parts.push((function(), theme.function, true)),
                    }
                    v.xrefs = Some(xref_chips(cx.db, listing, *entry));
                } else {
                    // A part away from the entry, by its place in the
                    // function (`main+1F40`).
                    let place = if from >= entry {
                        format!("{}+{:X}", function(), from - entry)
                    } else {
                        format!("{}-{:X}", function(), entry - from)
                    };
                    v.parts.push((place, theme.function, false));
                }
                v.meta = Some(size_text(to - from));
            }
            Some(Piece::Typed(key)) => {
                v.header = Header::Piece;
                v.kind = Some(Kind::Value);
                // A global or a header's table, by its row: its name, type,
                // size.
                let r = cx.tree_row(key)?;
                v.start = cx.cols.bytes + 2.0 * cw;
                v.type_column = Some(3 + r.name.chars().count() + 2);
                v.parts.push(("{} ".to_owned(), theme.type_, false));
                v.parts.push((r.name, theme.global, true));
                v.parts.push((format!("  {}", r.ty), theme.type_, false));
                if !r.value.is_empty() {
                    v.parts.push((format!("  {}", r.value), muted, false));
                }
                v.meta = Some(size_text(r.size));
            }
            Some(Piece::Bytes(range)) => {
                v.header = Header::Piece;
                v.start = cx.cols.bytes + 2.0 * cw;
                v.parts.push(("∷ ".to_owned(), muted, false));
                v.parts.push(("Untyped bytes".to_owned(), muted, false));
                v.meta = Some(size_text(range.end - range.start));
            }
            Some(Piece::Lines(_) | Piece::Uninitialised(_)) => {}
        }
        Some(())
    }

    /// A labelled block's header: its label on the left (a loop's head
    /// with its weight, its size said), its cross-references, the C it
    /// starts with.
    fn block_view(&self, cx: &RowsCtx<'_>, v: &mut RowView<'_>, n: u64) -> Option<()> {
        let theme = self.theme;
        let (doc, listing, ..) = cx.sources;
        let line = listing.line(n)?;
        v.header = Header::Block;
        v.kind = Some(Kind::Code);
        // It says no address: its first instruction, under it, does.
        v.place = (String::new(), theme.prefix(line.item));
        v.start = cx.cols.bytes + 2.0 * cx.cols.cw;
        if let Some(c) = cx.c_of(line.address) {
            v.snippet = self.block_snippet(c, line.address);
        }
        // A loop's head: a natural loop's header (folding the loop whole,
        // its size said), or where its C says so.
        let region = doc.loops.get(&line.address).map(|&end| end - line.address);
        let head = region.is_some()
            || v.snippet.first().is_some_and(|(text, ..)| {
                let text = text.trim_start_matches("} ");
                ["while", "for", "do"].iter().any(|k| {
                    text.strip_prefix(k).is_some_and(|rest| {
                        !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_')
                    })
                })
            });
        v.meta = region.map(|size| format!("loop · {}", size_text(size)));
        v.loop_head = head;
        // A plain block's label is a mark in the code (quiet, no rule); a
        // loop's head keeps its weight.
        v.parts.push((
            if head { "↻ " } else { "↳ " }.to_owned(),
            if head {
                theme.keyword
            } else {
                theme.text_placeholder
            },
            head,
        ));
        let label = cx
            .name(line.address)
            .unwrap_or_else(|| format!("loc_{:X}", line.address));
        v.parts.push((label, theme.label, head));
        v.xrefs = Some(xref_chips(cx.db, listing, line.address));
        Some(())
    }

    /// A listing line: its own address and bytes (a long string's piece
    /// too), its text past the listing's prefix (the highlighted token's
    /// equals lit, the find bar's matches marked), its item's
    /// cross-references as one badge, the C's link, the comment field's
    /// place on it.
    fn line_view(&self, cx: &RowsCtx<'_>, v: &mut RowView<'_>, n: u64) -> Option<()> {
        let theme = self.theme;
        let (_, listing, ..) = cx.sources;
        let line = listing.line(n)?;
        v.place.1 = theme.prefix(line.item);
        v.kind = cx.kinds(Some(line.address), None, 1).first().copied();
        if line.kind == LineKind::Instruction {
            v.linked_wash = if cx.hovered.binary_search(&line.address).is_ok() {
                Some(theme.selection)
            } else if cx.behind.binary_search(&line.address).is_ok() {
                Some(theme.provenance())
            } else {
                None
            };
            v.tint = cx
                .linked
                .as_ref()
                .and_then(|d| d.tint_of(line.address))
                .map(|t| theme.tint(t));
        }
        let mut rendered = listing.render(cx.db, n, cx.overlay);
        // The comment field's line without its comment.
        let field_here = cx.field.filter(|&(_, at, _)| at == n);
        if field_here.is_some()
            && rendered
                .tokens
                .last()
                .is_some_and(|t| t.role == Role::Comment)
        {
            let keep = rendered.tokens.len().saturating_sub(2);
            rendered.tokens.truncate(keep);
        }
        let (at, first_of_item) = self.line_place(cx, v, n, &rendered.tokens);
        // An item's references on its first line, whichever line the
        // listing writes them on (a long string's on a line of their own).
        let item_start = at == line.address;
        if line.kind == LineKind::Data && first_of_item && item_start {
            v.xrefs = Some(xref_chips(cx.db, listing, line.address));
        }
        // The listing's own prefix and its padding: the address column
        // says where, the text column lines up.
        let prefix = || {
            rendered
                .tokens
                .iter()
                .take_while(|t| matches!(t.role, Role::Prefix | Role::Space | Role::OpcodeBytes))
        };
        let skipped: usize = prefix().map(|t| t.text.chars().count()).sum();
        // The find bar's matches on the line, by the text's bytes past the
        // prefix.
        let past: usize = prefix().map(|t| t.text.len()).sum();
        v.marks = self
            .find_marks(cx.id, &FindKind::Listing, n)
            .into_iter()
            .filter(|(r, _)| r.end > past)
            .map(|(r, c)| (r.start.saturating_sub(past)..r.end - past, c))
            .collect();
        for t in rendered.tokens.iter().skip(prefix().count()) {
            if t.text.is_empty() {
                continue;
            }
            // The item's cross-references are one badge.
            if matches!(t.role, Role::CodeXref | Role::DataXref) {
                if v.xrefs.is_none() && item_start {
                    v.xrefs = Some(xref_chips(cx.db, listing, line.address));
                }
                continue;
            }
            let color = theme.token(t);
            // The highlighted name's (register's, number's) equals lit.
            let is_lit = t.role != Role::Space && cx.highlight == Some(t.text.as_str());
            // A long number in two tones by digit group.
            let mut rest = t.text.as_str();
            for (len, tone) in tones(&t.text, matches!(t.role, Role::Number)) {
                let cut = len.min(rest.len());
                let (head, tail) = if rest.is_char_boundary(cut) {
                    rest.split_at(cut)
                } else {
                    (rest, "")
                };
                rest = tail;
                if is_lit {
                    v.lit.push(v.parts.len());
                }
                let c = if tone { dim(color) } else { color };
                v.parts.push((head.to_owned(), c, false));
            }
        }
        if v.xrefs.is_some() || field_here.is_some() {
            // The padding to the comment column goes with them.
            while v.parts.last().is_some_and(|p| p.0.trim().is_empty()) {
                v.parts.pop();
            }
        }
        // `; ` at the comment column, the field after it.
        if let Some((_, _, column)) = field_here {
            let width: usize = v.parts.iter().map(|p| p.0.chars().count()).sum();
            let column = column.saturating_sub(skipped).max(width + 1);
            v.parts
                .push((" ".repeat(column - width), theme.text_placeholder, false));
            v.parts.push(("; ".to_owned(), theme.comment, false));
            v.comment_column = Some(column + 2);
        }
        Some(())
    }

    /// Line `n`'s own place (a data line's piece: a long string's, a
    /// table's entry, as the listing's prefix in `tokens` says) into
    /// `v`'s address column, and its bytes, up to the next piece's or
    /// item's (on its item's first content line, or a piece's); the place,
    /// and whether it is its item's first content line.
    fn line_place(
        &self,
        cx: &RowsCtx<'_>,
        v: &mut RowView<'_>,
        n: u64,
        tokens: &[Token],
    ) -> (u64, bool) {
        let (_, listing, ..) = cx.sources;
        let Some(line) = listing.line(n) else {
            return (0, false);
        };
        let piece_of = |tokens: &[Token]| {
            tokens
                .first()
                .filter(|t| t.role == Role::Prefix)
                .and_then(|t| t.target)
        };
        let at = piece_of(tokens).unwrap_or(line.address);
        if at != line.address {
            v.place.0 = format!("{at:0width$X}", width = cx.digits);
        }
        let content = matches!(line.kind, LineKind::Instruction | LineKind::Data);
        let previous = n.checked_sub(1).and_then(|m| listing.line(m));
        let first_of_item = previous.is_none_or(|l| {
            l.address != line.address || !matches!(l.kind, LineKind::Instruction | LineKind::Data)
        });
        if cx.cols.shows_bytes && content && (first_of_item || at != line.address) {
            let next = (n + 1..n + 16)
                .filter_map(|m| Some((m, listing.line(m)?)))
                .find_map(|(m, l)| {
                    if l.address != line.address {
                        return Some(l.address);
                    }
                    let piece = piece_of(&listing.render(cx.db, m, cx.overlay).tokens)?;
                    (l.kind == LineKind::Data && piece != at).then_some(piece)
                });
            let len = next.map_or(1, |a| a.saturating_sub(at));
            let hex = cx.hex_of(Some(at), None, len);
            v.byte_marks = self.hex_marks(cx, Some(at), len);
            v.bytes = Some(vec![(hex, self.theme.text_placeholder, false)]);
        }
        (at, first_of_item)
    }

    /// A tree row: its name, type and value in columns as wide as its
    /// siblings' widest (a very long one pushes on alone), its bytes, its
    /// offset in its global (or in its table of the file's headers).
    fn field_view(
        &self,
        cx: &RowsCtx<'_>,
        v: &mut RowView<'_>,
        key: &Key,
        (address, file_at): (Option<u64>, Option<u64>),
    ) {
        let theme = self.theme;
        let (_, _, _, overlays) = cx.sources;
        let Some(r) = cx.tree_row(key) else {
            return;
        };
        if cx.cols.shows_bytes {
            let hex = cx.hex_of(address, file_at, r.size);
            v.byte_marks = self.hex_marks(cx, address, r.size);
            v.bytes = Some(vec![(hex, theme.text_placeholder, false)]);
        }
        let (names, types) = self.field_columns(overlays, key);
        let names = names.min(FIELD_NAME_MOST);
        let types = types.min(FIELD_TYPE_MOST);
        v.type_column = Some(r.name.chars().count().max(names) + 1);
        v.parts
            .push((format!("{:<names$}", r.name), theme.field, false));
        if r.value.is_empty() {
            v.parts.push((format!(" {}", r.ty), theme.type_, false));
        } else {
            v.parts
                .push((format!(" {:<types$}", r.ty), theme.type_, false));
            v.parts.push((" = ".to_owned(), theme.punctuation, false));
            v.parts.push((r.value, theme.number, false));
        }
        // A member's offset in its global, or in its table of the file's
        // headers (the overlay's first step).
        let header = overlays
            .get(key.root)
            .is_some_and(|o| o.source == Source::Header);
        let table = key
            .steps
            .first()
            .filter(|_| header)
            .and_then(|&step| hex_tree::resolve(overlays, &Key::root(key.root).child(step)));
        let own = key.steps.len() > usize::from(header);
        let from = table.map_or(0, |t| t.offset);
        v.meta = own.then(|| format!("+{:X}", r.offset.saturating_sub(from)));
    }

    /// A row of untyped bytes: each in its kind's colour (as the hex
    /// view) in the bytes column, their characters in the text column;
    /// without the bytes column, both there.
    fn hex_row_view(
        &self,
        cx: &RowsCtx<'_>,
        v: &mut RowView<'_>,
        range: &Range<u64>,
        (address, file_at): (Option<u64>, Option<u64>),
    ) {
        let theme = self.theme;
        let cells = cx.kinds(address, file_at, range.end - range.start);
        v.kind = cells.first().copied();
        let mut hex: Vec<Part> = Vec::new();
        let mut marks: Vec<(Range<usize>, u32)> = Vec::new();
        let mut chars = String::new();
        for (i, at) in range.clone().enumerate() {
            let Some(b) = cx.byte_at(at) else {
                continue;
            };
            // The find bar's match on it: its two digits.
            if let Some(color) = address.and_then(|a| self.find_hex_mark(cx.id, a + i as u64)) {
                let x = hex.len() * 3;
                marks.push((x..x + 2, color));
            }
            let color = if b == 0 {
                theme.text_placeholder
            } else {
                cells
                    .get(i)
                    .and_then(|&k| kind_color(theme, k))
                    .unwrap_or(theme.text)
            };
            hex.push((format!("{b:02X} "), color, false));
            chars.push(if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '·'
            });
        }
        if cx.cols.shows_bytes {
            v.bytes = Some(hex);
            v.byte_marks = marks;
            v.parts.push((chars, theme.string, false));
        } else {
            v.start = cx.cols.bytes;
            v.parts = hex;
            v.marks = marks;
            v.parts.push((format!(" {chars}"), theme.string, false));
        }
    }

    /// The find bar's byte matches among the bytes from `address` a row
    /// shows as hex ([`RowsCtx::hex_of`], at most [`BYTES_SHOWN`] of
    /// `len`): each byte's two digits.
    fn hex_marks(
        &self,
        cx: &RowsCtx<'_>,
        address: Option<u64>,
        len: u64,
    ) -> Vec<(Range<usize>, u32)> {
        let Some(address) = address else {
            return Vec::new();
        };
        (0..len.min(BYTES_SHOWN as u64))
            .filter_map(|i| {
                let color = self.find_hex_mark(cx.id, address + i)?;
                let x = usize::try_from(i).ok()? * 3;
                Some((x..x + 2, color))
            })
            .collect()
    }
}

/// What a section card says of its section's kind (none for a plain
/// section).
fn section_title(kind: Kind) -> String {
    match kind {
        Kind::Section => String::new(),
        Kind::Header
        | Kind::Table
        | Kind::Code
        | Kind::LooseCode
        | Kind::String
        | Kind::Pointer
        | Kind::Import
        | Kind::Value
        | Kind::Relocation
        | Kind::Padding
        | Kind::Unexplored
        | Kind::Other
        | Kind::Uninitialised
        | Kind::Gap => kind.title().to_owned(),
    }
}
