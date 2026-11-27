//! The unified listing without the framework (an experiment:
//! `research/unified-listing-design.md`): one document of the whole file
//! in file order, each part of it an item under a card that folds it, the
//! layers switchable.
//!
//! - **Items** ([`Document::items`]): the file's parts
//!   ([`HexImage::parts`]): its headers and tables (the header overlay's
//!   members, as their trees), its sections, the bytes no part holds; a
//!   section the file does not supply (`.bss`) after the mapped item
//!   before it.
//! - **Pieces** of a section ([`Piece`]): a function (its listing lines
//!   under a card), listing lines (data, code no function holds), a typed
//!   global (an overlay's tree under a card), untyped bytes (hex rows, a
//!   run of one value one row), bytes the file does not supply.
//! - **Rows** ([`Document::flatten`]): the cards and what the open ones
//!   hold, as the pane's folds and layers say; one height each.

use std::collections::{BTreeMap, HashSet};
use std::ops::Range;
use std::sync::Arc;

use binbun::cfg::{BlockId, Program};
use binbun::listing::SpanKind;

use crate::hex::{Anchor, HexImage, Kind, Mode, Overlay, Part, Source, span_kind};
use crate::hex_tree::{self, Key, Step, StructTree};
use crate::listing::{Item as LineItem, LineKind, Listing};
use crate::scroll::{Scroller, Sideways};
use crate::selection::Lines;

/// The fewest bytes of one value shown as one row.
pub const RUN: u64 = 32;
/// The fewest untyped bytes given a card of their own.
const BYTES_CARD: u64 = 64;
/// The most untyped bytes under a card open from the start.
const BYTES_OPEN: u64 = 256;
/// The fewest bytes outside every part given a card.
const OUTSIDE_CARD: u64 = 256;
/// How many parts a section's strip has.
pub const STRIP: usize = 96;
/// How many bytes past a table's last entry its part may hold and still be
/// the table's (a partial entry, padding).
const TABLE_SLACK: u64 = 64;
/// How many parts the overview of a pane's rows has.
pub const OVERVIEW: usize = 400;
/// Untyped bytes a hex row shows (the bytes column's).
pub const HEX_ROW: u64 = 8;

/// What an item is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemKind {
    /// A header or table of the file: the header overlay's member `0`.
    Header(Key),
    /// A section, of its part's kind ([`Kind::Uninitialised`]: one the
    /// file does not supply).
    Section(Kind),
    /// File bytes no part holds.
    Outside,
}

/// A part of the document under its card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// What it is.
    pub kind: ItemKind,
    /// Its name (`ELF header`, `.text`); empty for bytes outside.
    pub name: String,
    /// Its file offsets (empty for a section the file does not supply,
    /// at the offset it is shown at).
    pub file: Range<u64>,
    /// Its addresses, if it is mapped.
    pub address: Option<Range<u64>>,
    /// What a section or the bytes outside hold, in order.
    pub pieces: Vec<Piece>,
    /// What a mapped section holds, in [`STRIP`] equal parts from its
    /// start: each part's kind of most bytes (empty for the others).
    pub strip: Vec<Kind>,
}

/// A piece of a section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    /// Instructions of the function at `entry`, from `start` (its entry,
    /// or a part of it elsewhere) to `end`: its lines.
    Function {
        /// The function's entry.
        entry: u64,
        /// The first address.
        start: u64,
        /// Past the last.
        end: u64,
        /// Its listing lines.
        lines: Range<u64>,
    },
    /// Listing lines: data, code no function holds.
    Lines(Range<u64>),
    /// A typed global, or a header's table within a part: its tree's row.
    Typed(Key),
    /// Untyped bytes, by file offset.
    Bytes(Range<u64>),
    /// Mapped bytes the file does not supply, by address.
    Uninitialised(Range<u64>),
}

/// The layers a pane shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layers {
    /// The instructions' bytes, in a column.
    pub bytes: bool,
    /// Untyped bytes as hex rows (else one row each run).
    pub hex: bool,
    /// The file's structure: its headers, its tables, what is not mapped.
    pub structure: bool,
}

impl Default for Layers {
    fn default() -> Self {
        Self {
            bytes: true,
            hex: true,
            structure: true,
        }
    }
}

/// What folds without a tree of its own, by where it starts: a card's
/// open state is its default unless the user flipped it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Fold {
    /// An item: its first file offset and address.
    Item(u64, Option<u64>),
    /// A function piece: its first address.
    Function(u64),
    /// Untyped bytes: their first file offset.
    Bytes(u64),
    /// A labelled block of a function: its label's address.
    Block(u64),
}

/// What a row shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowKind {
    /// Item `item`'s card, or its piece `piece`'s; whether it is open.
    Card {
        /// The item.
        item: usize,
        /// The piece, for a piece's card.
        piece: Option<usize>,
        /// Whether what it holds is shown.
        open: bool,
    },
    /// A listing line.
    Line(u64),
    /// A labelled block of a function: its label's line (the block's
    /// header), whether its lines are shown.
    Block {
        /// The label's line.
        line: u64,
        /// Whether the block's lines are shown.
        open: bool,
    },
    /// A line of an overlay's tree under its card.
    Field(hex_tree::Line),
    /// Untyped bytes of one row (at most [`HEX_ROW`], within one
    /// [`HEX_ROW`] boundary), by file offset.
    Hex(Range<u64>),
    /// A run of one byte value, by file offset.
    Run {
        /// Its bytes.
        file: Range<u64>,
        /// The value.
        byte: u8,
    },
    /// Untyped bytes as one row (the hex layer off), by file offset.
    Bytes(Range<u64>),
    /// Bytes the file does not supply, by address.
    Uninitialised(Range<u64>),
    /// An empty row before a function's card, setting the functions
    /// apart.
    Spacer,
}

/// A row: what it shows and how deep it is (an item's card: 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// What it shows.
    pub kind: RowKind,
    /// How deep.
    pub depth: u8,
}

impl Row {
    /// Whether it is `other`'s row, open or not.
    pub fn same(&self, other: &Self) -> bool {
        match (&self.kind, &other.kind) {
            (
                RowKind::Card { item, piece, .. },
                RowKind::Card {
                    item: i, piece: p, ..
                },
            ) => item == i && piece == p,
            (RowKind::Field(a), RowKind::Field(b)) => a.key == b.key,
            (RowKind::Block { line: a, .. }, RowKind::Block { line: b, .. }) => a == b,
            (a, b) => a == b,
        }
    }
}

/// The rows as a pane's folds and layers say, and each item's.
#[derive(Clone, Debug, Default)]
pub struct Flat {
    /// The rows.
    pub rows: Vec<Row>,
    /// Each item's rows.
    items: Vec<Range<usize>>,
    /// The rows in [`OVERVIEW`] equal parts (or a part a row): each
    /// part's kind of most rows (`None`: rows of no kind, cards).
    pub overview: Vec<Option<Kind>>,
}

impl Flat {
    /// How many rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The index of `row` (open or not).
    pub fn find(&self, row: &Row) -> Option<usize> {
        self.rows.iter().position(|r| r.same(row))
    }

    /// The headers holding row `first` (the first on screen), outermost
    /// first, to pin at the top while their items scroll by: its item's
    /// card, its piece's, its block's (a function's lines are its block's
    /// as deep as its header).
    pub fn sticky(&self, first: usize) -> Vec<usize> {
        let mut chain = Vec::new();
        let Some(row) = self.rows.get(first) else {
            return chain;
        };
        let mut depth = row.depth;
        // A function's line looks for its block's header first.
        let mut block = matches!(row.kind, RowKind::Line(_)) && depth == 2;
        for j in (0..first).rev() {
            let Some(r) = self.rows.get(j) else {
                break;
            };
            let holds = match r.kind {
                RowKind::Block { .. } => block,
                RowKind::Card { .. } => r.depth < depth,
                RowKind::Line(_)
                | RowKind::Field(_)
                | RowKind::Hex(_)
                | RowKind::Run { .. }
                | RowKind::Bytes(_)
                | RowKind::Uninitialised(_)
                | RowKind::Spacer => false,
            };
            if holds {
                chain.push(j);
                depth = r.depth;
                block = false;
                if depth == 0 {
                    break;
                }
            }
        }
        chain.reverse();
        chain
    }

    /// The headers pinned at the top with row `first` the first on screen,
    /// outermost first: level by level, the header holding the row just
    /// under the levels so far, so a header makes way (is gone) as the
    /// next item's comes up under it rather than hiding it.
    pub fn pinned(&self, first: usize) -> Vec<usize> {
        let mut pinned: Vec<usize> = Vec::new();
        loop {
            let level = pinned.len();
            let chain = self.sticky(first + level);
            if chain.get(..level) != Some(pinned.as_slice()) {
                break;
            }
            match chain.get(level) {
                Some(&header) => pinned.push(header),
                None => break,
            }
        }
        pinned
    }
}

/// What a tab keeps of its unified listing: the layers, the folds flipped
/// from their default (in order).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnifiedView {
    /// The layers.
    pub layers: Layers,
    /// The folds flipped.
    pub folds: Vec<Fold>,
    /// The trees' rows expanded (in order).
    pub expanded: Vec<Expanded>,
}

/// A tree's row expanded, by its overlay's place rather than its index
/// (the index changes as a session lays out its globals) and the steps to
/// it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Expanded {
    /// Its overlay's place.
    pub anchor: Anchor,
    /// The steps from the overlay's row.
    pub steps: Vec<Step>,
}

/// A unified listing pane: on or off, its layers, its folds, the cursor
/// (a row), the scrolling, the rows as last flattened.
#[derive(Debug, Default)]
pub struct UnifiedPane {
    /// Whether the pane's listing tab shows it.
    pub on: bool,
    /// What it shows.
    pub layers: Layers,
    /// The folds flipped from their default.
    flipped: HashSet<Fold>,
    /// The overlays' trees' state.
    pub tree: StructTree,
    /// The cursor's row.
    pub cursor: usize,
    /// The rows selected, from the anchor to the cursor (rows of the
    /// rows as flattened: a reflow drops it).
    pub selection: Lines,
    /// The scrolling, by row.
    pub scroll: Scroller,
    /// The sideways scrolling.
    pub side: Sideways,
    /// An address to move the cursor to, and whether as a jump.
    pub target: Option<(u64, bool)>,
    /// The row a jump landed on, and when (it is lit a moment).
    pub landed: Option<(usize, std::time::Instant)>,
    /// The rows as last flattened (`None`: flattened again).
    pub flat: Option<Arc<Flat>>,
    /// Rows to expand whose overlays were not laid out when they were
    /// asked for ([`Self::set_view`]).
    pending: Vec<Expanded>,
}

impl UnifiedPane {
    /// Whether `fold` is open, `default` unless flipped.
    pub fn is_open(&self, fold: Fold, default: bool) -> bool {
        default != self.flipped.contains(&fold)
    }

    /// Its layers, folds and expanded rows (those of `overlays`, and those
    /// still to expand), to keep with its tab.
    pub fn view(&self, overlays: &[Overlay]) -> UnifiedView {
        let mut folds: Vec<Fold> = self.flipped.iter().copied().collect();
        folds.sort_unstable();
        let mut expanded: Vec<Expanded> = self
            .tree
            .expanded()
            .filter_map(|key| {
                Some(Expanded {
                    anchor: overlays.get(key.root)?.anchor,
                    steps: key.steps.clone(),
                })
            })
            .chain(self.pending.iter().cloned())
            .collect();
        expanded.sort_unstable();
        expanded.dedup();
        UnifiedView {
            layers: self.layers,
            folds,
            expanded,
        }
    }

    /// Shows `view`'s layers, folds and expanded rows (a tab's, shown
    /// again; its rows expanded once their overlays are there:
    /// [`Self::expand_pending`]); the rows flattened again.
    pub fn set_view(&mut self, view: &UnifiedView) {
        self.layers = view.layers;
        self.flipped = view.folds.iter().copied().collect();
        self.tree = StructTree::default();
        self.pending.clone_from(&view.expanded);
        self.flat = None;
    }

    /// Expands the rows [`Self::set_view`] asked for whose overlays are in
    /// `overlays` now (by their places); whether any was.
    pub fn expand_pending(&mut self, overlays: &[Overlay]) -> bool {
        let before = self.pending.len();
        let tree = &mut self.tree;
        self.pending.retain(|row| {
            let Some(root) = overlays.iter().position(|o| o.anchor == row.anchor) else {
                return true;
            };
            tree.expand(Key {
                root,
                steps: row.steps.clone(),
            });
            false
        });
        let expanded = self.pending.len() < before;
        if expanded {
            self.flat = None;
        }
        expanded
    }

    /// Flips `fold`; the rows flattened again.
    pub fn flip(&mut self, fold: Fold) {
        if !self.flipped.remove(&fold) {
            self.flipped.insert(fold);
        }
        self.flat = None;
    }

    /// The cursor on row `row` of `flat` (at most its last), the view
    /// scrolled as `how` says with `visible` rows on screen.
    pub fn land(&mut self, flat: &Flat, row: usize, how: Landing, visible: u64) {
        let row = row.min(flat.len().saturating_sub(1));
        self.cursor = row;
        let (at, total) = (row as u64, flat.len() as u64);
        match how {
            Landing::Step => {
                // Below the headers that would be pinned over it.
                let margin = flat.sticky(row).len().max(1) as u64;
                self.scroll.reveal(at, total, visible, margin);
            }
            Landing::Follow => {
                let margin = (visible / 3).max(flat.sticky(row).len() as u64);
                self.scroll.reveal(at, total, visible, margin);
            }
            Landing::Jump => {
                self.scroll.smooth.stop();
                self.scroll.anchor.focus(at, total, visible);
                self.clear_of_pinned(flat, row);
            }
            Landing::Kept(screen) => {
                self.scroll.smooth.stop();
                self.scroll.anchor.line = at.saturating_sub(screen);
                self.scroll.anchor.offset = 0.0;
                self.scroll.anchor.reveal(at, total, visible, 0);
                self.clear_of_pinned(flat, row);
            }
        }
    }

    /// The view up as little as it takes for row `row` not to be under
    /// the headers pinned at the top.
    fn clear_of_pinned(&mut self, flat: &Flat, row: usize) {
        for _ in 0..8 {
            let top = usize::try_from(self.scroll.anchor.line).unwrap_or(0);
            if top == 0 || row >= top + flat.pinned(top).len() {
                break;
            }
            self.scroll.anchor.line -= 1;
            self.scroll.anchor.offset = 0.0;
        }
    }
}

/// How a pane's cursor comes to a row ([`UnifiedPane::land`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Landing {
    /// A key or a click: the row revealed, below the headers pinned over
    /// it.
    Step,
    /// The sync group moved it: revealed a third of the way in.
    Follow,
    /// A jump: the row near the top, clear of the pinned headers.
    Jump,
    /// The rows made again: the row as many rows from the top as it was.
    Kept(u64),
}

/// The document: its items in file order.
#[derive(Clone, Debug, Default)]
pub struct Document {
    /// The items.
    pub items: Vec<Item>,
    /// The loops a block's header folds whole: a natural loop's header's
    /// address to the end of its blocks, where they run on unbroken
    /// ([`loop_regions`]).
    pub loops: Arc<BTreeMap<u64, u64>>,
}

/// What a document is flattened from besides itself.
#[derive(Clone, Copy, Debug)]
pub struct Inputs<'a> {
    /// The overlays (the typed globals and headers).
    pub overlays: &'a [Overlay],
    /// The listing.
    pub listing: &'a Listing,
    /// The file's bytes (runs of one value are found in them).
    pub file: &'a [u8],
}

/// A typed global placed (an overlay of its own, or a header's table
/// within a part): its tree's row, address (if mapped), file offset (if
/// the file supplies it) and size.
#[derive(Clone, Debug)]
struct Global {
    key: Key,
    address: Option<u64>,
    file: Option<u64>,
    size: u64,
}

impl Document {
    /// The document of `image`, its sections' contents from `listing`, its
    /// typed globals and headers from `overlays`, the loops its headers
    /// fold ([`loop_regions`]).
    pub fn build(
        image: &HexImage,
        listing: &Listing,
        overlays: &[Overlay],
        loops: Arc<BTreeMap<u64, u64>>,
    ) -> Self {
        // The parts, outermost (a part inside another, or overlapping it,
        // is the outer's); the header members that are parts' items.
        let mut parts: Vec<&Part> = Vec::new();
        for part in image.parts() {
            if parts.last().is_none_or(|p| part.file.start >= p.file.end) {
                parts.push(part);
            }
        }
        let headers: Vec<Option<Key>> = parts
            .iter()
            .map(|part| header_member(image, overlays, part))
            .collect();
        let mut globals: Vec<Global> = overlays
            .iter()
            .enumerate()
            .filter(|(_, o)| o.source != Source::Header)
            .map(|(overlay, o)| Global {
                key: Key::root(overlay),
                address: image
                    .place(o.anchor, Mode::Address)
                    .filter(|&a| image.holds(Mode::Address, a)),
                file: image.place(o.anchor, Mode::File),
                size: o.layout.size.max(1),
            })
            .collect();
        // The headers' other tables, within parts (a PE's directories in
        // its sections, a Mach-O's load commands).
        globals.extend(
            header_members(image, overlays)
                .filter(|(key, ..)| !headers.contains(&Some(key.clone())))
                .map(|(key, file, size)| Global {
                    key,
                    address: image
                        .to_address(file)
                        .filter(|&a| image.holds(Mode::Address, a)),
                    file: Some(file),
                    size: size.max(1),
                }),
        );
        globals.sort_by_key(|g| (g.address, g.file));
        let mut items = Vec::new();
        let mut at = 0;
        for (part, header) in parts.into_iter().zip(headers) {
            if part.file.start > at {
                items.push(outside(image, &globals, at..part.file.start));
            }
            let address = image
                .to_address(part.file.start)
                .map(|a| a..a + (part.file.end - part.file.start));
            let (kind, pieces, strip) = match (header, &address) {
                (Some(key), _) => (ItemKind::Header(key), Vec::new(), Vec::new()),
                (None, Some(range)) => (
                    ItemKind::Section(part.kind),
                    mapped_pieces(listing, image, &globals, range.clone()),
                    strip(listing, &globals, range.clone()),
                ),
                (None, None) => (
                    ItemKind::Section(part.kind),
                    file_pieces(&globals, part.file.clone()),
                    Vec::new(),
                ),
            };
            items.push(Item {
                kind,
                name: part.name.clone(),
                file: part.file.clone(),
                address,
                pieces,
                strip,
            });
            at = part.file.end;
        }
        if at < image.file_len() {
            items.push(outside(image, &globals, at..image.file_len()));
        }
        insert_unsupplied(&mut items, image, listing, &globals);
        Self { items, loops }
    }

    /// Whether item `item` has a card (small runs of bytes outside every
    /// part have none).
    fn carded(item: &Item) -> bool {
        item.kind != ItemKind::Outside || item.file.end - item.file.start >= OUTSIDE_CARD
    }

    /// Item `item`'s fold and whether it is open by default (a mapped
    /// section is, but one only of many untyped bytes).
    fn item_fold(item: &Item) -> (Fold, bool) {
        let fold = Fold::Item(item.file.start, item.address.as_ref().map(|a| a.start));
        let open = match item.kind {
            ItemKind::Section(_) => {
                item.address.is_some()
                    && !matches!(item.pieces.as_slice(), [Piece::Bytes(r)] if r.end - r.start > BYTES_OPEN)
            }
            ItemKind::Header(_) | ItemKind::Outside => false,
        };
        (fold, open)
    }

    /// Whether the card of item `item` (its piece `piece`) is open.
    fn is_open(&self, pane: &UnifiedPane, item: usize, piece: Option<usize>) -> bool {
        let Some(it) = self.items.get(item) else {
            return false;
        };
        match piece.and_then(|p| it.pieces.get(p)) {
            None => match &it.kind {
                ItemKind::Header(key) => pane.tree.is_expanded(key),
                ItemKind::Section(_) | ItemKind::Outside => {
                    let (fold, open) = Self::item_fold(it);
                    pane.is_open(fold, open)
                }
            },
            Some(Piece::Function { start, .. }) => pane.is_open(Fold::Function(*start), true),
            Some(Piece::Typed(key)) => pane.tree.is_expanded(key),
            Some(Piece::Bytes(file)) => {
                pane.is_open(Fold::Bytes(file.start), file.end - file.start <= BYTES_OPEN)
            }
            Some(Piece::Lines(_) | Piece::Uninitialised(_)) => true,
        }
    }

    /// Opens or closes the card of item `item` (its piece `piece`).
    pub fn toggle(&self, pane: &mut UnifiedPane, item: usize, piece: Option<usize>) {
        let Some(it) = self.items.get(item) else {
            return;
        };
        match piece.and_then(|p| it.pieces.get(p)) {
            None => match &it.kind {
                ItemKind::Header(key) => pane.tree.toggle(key),
                ItemKind::Section(_) | ItemKind::Outside => pane.flip(Self::item_fold(it).0),
            },
            Some(Piece::Function { start, .. }) => pane.flip(Fold::Function(*start)),
            Some(Piece::Typed(key)) => pane.tree.toggle(key),
            Some(Piece::Bytes(file)) => pane.flip(Fold::Bytes(file.start)),
            Some(Piece::Lines(_) | Piece::Uninitialised(_)) => {}
        }
        pane.flat = None;
    }

    /// The rows `pane` shows: the cards, and what the open ones hold.
    pub fn flatten(&self, pane: &UnifiedPane, inputs: &Inputs<'_>) -> Flat {
        let mut out = Vec::new();
        let mut items = Vec::with_capacity(self.items.len());
        let hex = pane.layers.hex;
        for (i, item) in self.items.iter().enumerate() {
            let first = out.len();
            let structure = item.address.is_some() && !matches!(item.kind, ItemKind::Header(_));
            if !pane.layers.structure && !structure {
                items.push(first..first);
                continue;
            }
            if !Self::carded(item) {
                push_bytes(&mut out, inputs.file, item.file.clone(), 0, hex);
                items.push(first..out.len());
                continue;
            }
            let open = self.is_open(pane, i, None);
            out.push(Row {
                kind: RowKind::Card {
                    item: i,
                    piece: None,
                    open,
                },
                depth: 0,
            });
            if open {
                if let ItemKind::Header(key) = &item.kind {
                    push_tree(&mut out, &pane.tree, inputs.overlays, key, 0);
                }
                for (p, piece) in item.pieces.iter().enumerate() {
                    let alone = item.pieces.len() == 1;
                    self.push_piece(&mut out, pane, inputs, (i, p, alone), piece);
                }
            }
            items.push(first..out.len());
        }
        let mut flat = Flat {
            rows: out,
            items,
            overview: Vec::new(),
        };
        flat.overview = self.overview(&flat, inputs.listing);
        flat
    }

    /// The overview of `flat`: its rows in [`OVERVIEW`] parts, each
    /// part's kind of most rows.
    fn overview(&self, flat: &Flat, listing: &Listing) -> Vec<Option<Kind>> {
        let total = flat.rows.len();
        let parts = OVERVIEW.min(total);
        if parts == 0 {
            return Vec::new();
        }
        let mut counts = vec![[0u32; Kind::ALL.len()]; parts];
        for (item, rows) in self.items.iter().zip(&flat.items) {
            for k in rows.clone() {
                let Some(kind) = flat.rows.get(k).and_then(|r| row_kind(item, r, listing)) else {
                    continue;
                };
                let part = (k * parts / total).min(parts - 1);
                let i = Kind::ALL.iter().position(|&x| x == kind).unwrap_or(0);
                if let Some(c) = counts.get_mut(part).and_then(|c| c.get_mut(i)) {
                    *c += 1;
                }
            }
        }
        counts
            .iter()
            .map(|c| {
                c.iter()
                    .zip(Kind::ALL)
                    .filter(|&(&n, _)| n > 0)
                    .max_by_key(|&(&n, _)| n)
                    .map(|(_, kind)| kind)
            })
            .collect()
    }

    /// The rows of piece `piece` (item and piece `at`, and whether it is
    /// the item's only piece: untyped bytes then have no card of their
    /// own).
    fn push_piece(
        &self,
        out: &mut Vec<Row>,
        pane: &UnifiedPane,
        inputs: &Inputs<'_>,
        (item, p, alone): (usize, usize, bool),
        piece: &Piece,
    ) {
        let Inputs {
            overlays,
            listing,
            file,
        } = *inputs;
        let card = |out: &mut Vec<Row>| {
            let open = self.is_open(pane, item, Some(p));
            out.push(Row {
                kind: RowKind::Card {
                    item,
                    piece: Some(p),
                    open,
                },
                depth: 1,
            });
            open
        };
        match piece {
            Piece::Function { lines, entry, .. } => {
                // A function set apart from what is above it (but its
                // section's card, and its own part before it: padding
                // between them).
                let first = matches!(
                    out.last().map(|r| &r.kind),
                    None | Some(RowKind::Card { piece: None, .. } | RowKind::Spacer)
                );
                let own_part = self.items.get(item).is_some_and(|it| {
                    it.pieces
                        .get(..p)
                        .unwrap_or_default()
                        .iter()
                        .rev()
                        .find(|q| !matches!(q, Piece::Bytes(_) | Piece::Uninitialised(_)))
                        .is_some_and(
                            |q| matches!(q, Piece::Function { entry: e, .. } if e == entry),
                        )
                });
                if !first && !own_part {
                    out.push(Row {
                        kind: RowKind::Spacer,
                        depth: 1,
                    });
                }
                if card(out) {
                    push_function(out, pane, (listing, &self.loops), lines.clone());
                }
            }
            Piece::Lines(lines) => push_lines(out, listing, lines.clone(), 1),
            Piece::Typed(key) => {
                // A scalar global is one row, as a field.
                let root = pane.tree.lines_under(overlays, key).into_iter().next();
                match root {
                    Some(line) if !line.expandable => out.push(Row {
                        kind: RowKind::Field(line),
                        depth: 1,
                    }),
                    Some(_) | None => {
                        if card(out) {
                            push_tree(out, &pane.tree, overlays, key, 1);
                        }
                    }
                }
            }
            Piece::Bytes(range)
                if alone || !pane.layers.hex || range.end - range.start < BYTES_CARD =>
            {
                push_bytes(out, file, range.clone(), 1, pane.layers.hex);
            }
            Piece::Bytes(range) => {
                if card(out) {
                    push_bytes(out, file, range.clone(), 2, true);
                }
            }
            Piece::Uninitialised(range) => out.push(Row {
                kind: RowKind::Uninitialised(range.clone()),
                depth: 1,
            }),
        }
    }

    /// The first address of piece `piece`.
    pub fn piece_address(piece: &Piece, image: &HexImage, overlays: &[Overlay]) -> Option<u64> {
        match piece {
            Piece::Function { start, .. } => Some(*start),
            Piece::Lines(_) => None,
            Piece::Typed(key) => typed_place(key, image, overlays, Mode::Address)
                .filter(|&a| image.holds(Mode::Address, a)),
            Piece::Bytes(file) => image.to_address(file.start),
            Piece::Uninitialised(range) => Some(range.start),
        }
    }

    /// The address `row` starts at, if it is mapped.
    pub fn address(
        &self,
        row: &Row,
        listing: &Listing,
        image: &HexImage,
        overlays: &[Overlay],
    ) -> Option<u64> {
        match &row.kind {
            RowKind::Card { item, piece, .. } => {
                let item = self.items.get(*item)?;
                match piece {
                    None => item.address.as_ref().map(|a| a.start),
                    Some(p) => Self::piece_address(item.pieces.get(*p)?, image, overlays),
                }
            }
            RowKind::Line(n) => listing.line(*n).map(|l| l.address),
            RowKind::Block { line, .. } => listing.line(*line).map(|l| l.address),
            RowKind::Field(line) => {
                let overlay = overlays.get(line.key.root)?;
                let found = hex_tree::resolve(overlays, &line.key)?;
                image
                    .position(overlay, Mode::Address, found.offset)
                    .filter(|&a| image.holds(Mode::Address, a))
            }
            RowKind::Hex(file) | RowKind::Bytes(file) | RowKind::Run { file, .. } => {
                image.to_address(file.start)
            }
            RowKind::Uninitialised(range) => Some(range.start),
            RowKind::Spacer => None,
        }
    }

    /// The listing line `row` stands for, for the listing's cursor and
    /// the sync group: a line's own (a long string's piece, a label),
    /// else its address's first; none for a row of no address.
    pub fn listing_line(
        &self,
        row: &Row,
        listing: &Listing,
        image: &HexImage,
        overlays: &[Overlay],
    ) -> Option<u64> {
        let address = self.address(row, listing, image, overlays)?;
        Some(match &row.kind {
            RowKind::Line(n) | RowKind::Block { line: n, .. } => *n,
            RowKind::Card { .. }
            | RowKind::Field(_)
            | RowKind::Hex(_)
            | RowKind::Run { .. }
            | RowKind::Bytes(_)
            | RowKind::Uninitialised(_)
            | RowKind::Spacer => listing.line_of(address),
        })
    }

    /// The file offset `row` starts at, if the file supplies it.
    pub fn offset(&self, row: &Row, image: &HexImage, overlays: &[Overlay]) -> Option<u64> {
        match &row.kind {
            RowKind::Card { item, piece, .. } => {
                let item = self.items.get(*item)?;
                match piece.and_then(|p| item.pieces.get(p)) {
                    None => (!item.file.is_empty()).then_some(item.file.start),
                    Some(Piece::Bytes(file)) => Some(file.start),
                    Some(Piece::Typed(key)) => typed_place(key, image, overlays, Mode::File),
                    Some(Piece::Function { start, .. }) => image.to_file(*start),
                    Some(Piece::Lines(_) | Piece::Uninitialised(_)) => None,
                }
            }
            RowKind::Field(line) => {
                let overlay = overlays.get(line.key.root)?;
                let found = hex_tree::resolve(overlays, &line.key)?;
                image.position(overlay, Mode::File, found.offset)
            }
            RowKind::Hex(file) | RowKind::Bytes(file) | RowKind::Run { file, .. } => {
                Some(file.start)
            }
            RowKind::Line(_)
            | RowKind::Block { .. }
            | RowKind::Uninitialised(_)
            | RowKind::Spacer => None,
        }
    }

    /// The row of `flat` at `address`: the last whose address is at or
    /// before it in the item holding it, its content line rather than its
    /// labels and cross-references; a closed card if the address is
    /// under it.
    pub fn row_of(
        &self,
        flat: &Flat,
        address: u64,
        listing: &Listing,
        image: &HexImage,
        overlays: &[Overlay],
    ) -> Option<usize> {
        let item = self
            .items
            .iter()
            .position(|i| i.address.as_ref().is_some_and(|a| a.contains(&address)))?;
        let rows = flat.items.get(item)?.clone();
        // A spacer is where the card after it is (the search stays in
        // order).
        let start = |k: usize| {
            let k = if flat.rows.get(k)?.kind == RowKind::Spacer {
                k + 1
            } else {
                k
            };
            flat.rows
                .get(k)
                .and_then(|r| self.address(r, listing, image, overlays))
        };
        let after = rows.start
            + (rows.start..rows.end)
                .collect::<Vec<_>>()
                .partition_point(|&k| start(k).is_none_or(|a| a <= address));
        // Not a spacer (it has no address of its own): the row above it.
        let spacer = |k: usize| flat.rows.get(k).is_some_and(|r| r.kind == RowKind::Spacer);
        let mut last = after.checked_sub(1).filter(|&k| k >= rows.start)?;
        while spacer(last) && last > rows.start {
            last -= 1;
        }
        // Back over the item's other lines at the same address to its
        // content line.
        let at = start(last);
        let mut best = last;
        let mut k = last;
        while k > rows.start && start(k - 1) == at {
            k -= 1;
            let content = flat.rows.get(k).is_some_and(|r| match r.kind {
                RowKind::Line(n) => listing
                    .line(n)
                    .is_some_and(|l| matches!(l.kind, LineKind::Instruction | LineKind::Data)),
                RowKind::Card { .. }
                | RowKind::Field(_)
                | RowKind::Hex(_)
                | RowKind::Run { .. }
                | RowKind::Bytes(_)
                | RowKind::Uninitialised(_)
                | RowKind::Block { .. }
                | RowKind::Spacer => false,
            });
            if content {
                best = k;
            }
        }
        Some(best)
    }
}

/// Where tree row `key` (a typed piece's) starts, in `mode`.
fn typed_place(key: &Key, image: &HexImage, overlays: &[Overlay], mode: Mode) -> Option<u64> {
    let overlay = overlays.get(key.root)?;
    let found = hex_tree::resolve(overlays, key)?;
    image.position(overlay, mode, found.offset)
}

/// The header overlays' members: each one's key, file offset and size.
fn header_members<'a>(
    image: &'a HexImage,
    overlays: &'a [Overlay],
) -> impl Iterator<Item = (Key, u64, u64)> + 'a {
    overlays
        .iter()
        .enumerate()
        .filter(|(_, o)| o.source == Source::Header)
        .filter_map(|(root, o)| Some((root, image.place(o.anchor, Mode::File)?)))
        .flat_map(move |(root, base)| {
            (0..).map_while(move |i| {
                let key = Key::root(root).child(Step::Member(i));
                let found = hex_tree::resolve(overlays, &key)?;
                Some((key, base + found.offset, found.size))
            })
        })
}

/// The key of the header overlay's member that is part `part`: one at its
/// start covering it (a table's last, partial entry aside).
fn header_member(image: &HexImage, overlays: &[Overlay], part: &Part) -> Option<Key> {
    let len = part.file.end - part.file.start;
    header_members(image, overlays)
        .find(|&(_, file, size)| file == part.file.start && size + TABLE_SLACK >= len)
        .map(|(key, ..)| key)
}

/// File bytes `file` no part holds, the typed globals there.
fn outside(image: &HexImage, globals: &[Global], file: Range<u64>) -> Item {
    Item {
        kind: ItemKind::Outside,
        name: String::new(),
        address: image
            .to_address(file.start)
            .map(|a| a..a + (file.end - file.start)),
        pieces: file_pieces(globals, file.clone()),
        strip: Vec::new(),
        file,
    }
}

/// What the mapped addresses `range` hold, in [`STRIP`] equal parts (or a
/// part a byte): each part's kind of most bytes, by the listing's items
/// and the typed globals over them ([`Kind::Gap`] where nothing is).
fn strip(listing: &Listing, globals: &[Global], range: Range<u64>) -> Vec<Kind> {
    let len = range.end.saturating_sub(range.start);
    let parts = u64::try_from(STRIP).unwrap_or(1).min(len);
    if parts == 0 {
        return Vec::new();
    }
    // Part `p` starts here (from the range's start).
    let boundary =
        |p: u64| u64::try_from(u128::from(p) * u128::from(len) / u128::from(parts)).unwrap_or(len);
    let part_of = |offset: u64| {
        u64::try_from(u128::from(offset) * u128::from(parts) / u128::from(len))
            .unwrap_or(0)
            .min(parts - 1)
    };
    let mut counts = vec![[0u64; Kind::ALL.len()]; usize::try_from(parts).unwrap_or(0)];
    let mut add = |bytes: Range<u64>, kind: Kind| {
        let k = Kind::ALL.iter().position(|&x| x == kind).unwrap_or(0);
        let end = bytes.end.min(range.end).saturating_sub(range.start);
        let mut at = bytes.start.max(range.start).saturating_sub(range.start);
        while at < end {
            let p = part_of(at);
            let next = boundary(p + 1).max(at + 1).min(end);
            if let Some(c) = usize::try_from(p)
                .ok()
                .and_then(|p| counts.get_mut(p))
                .and_then(|c| c.get_mut(k))
            {
                *c += next - at;
            }
            at = next;
        }
    };
    for span in listing.lines().spans(range.clone()) {
        add(span.start..span.end, span_kind(&span).0);
    }
    for g in globals {
        if let Some(a) = g.address.filter(|a| range.contains(a)) {
            add(a..a + g.size, Kind::Value);
        }
    }
    counts
        .iter()
        .map(|c| {
            c.iter()
                .zip(Kind::ALL)
                .filter(|&(&n, _)| n > 0)
                .max_by_key(|&(&n, _)| n)
                .map_or(Kind::Gap, |(_, kind)| kind)
        })
        .collect()
}

/// The pieces of file bytes `file` no listing describes: the typed
/// globals placed by file offset alone, the rest bytes.
fn file_pieces(globals: &[Global], file: Range<u64>) -> Vec<Piece> {
    let mut out = Vec::new();
    let mut at = file.start;
    let mut placed: Vec<&Global> = globals
        .iter()
        .filter(|g| g.address.is_none() && g.file.is_some_and(|f| file.contains(&f)))
        .collect();
    placed.sort_by_key(|g| g.file);
    for g in placed {
        let start = g.file.unwrap_or(at);
        if start < at {
            continue;
        }
        push_piece(&mut out, Piece::Bytes(at..start));
        out.push(Piece::Typed(g.key.clone()));
        at = (start + g.size).min(file.end);
    }
    push_piece(&mut out, Piece::Bytes(at..file.end));
    out
}

/// The pieces of the mapped addresses `range`: the listing's items, the
/// typed globals over them (over untyped bytes they split them; over an
/// item, after it).
fn mapped_pieces(
    listing: &Listing,
    image: &HexImage,
    globals: &[Global],
    range: Range<u64>,
) -> Vec<Piece> {
    let lines = listing.lines();
    let spans = lines.spans(range.clone());
    let globals: Vec<&Global> = globals
        .iter()
        .filter(|g| g.address.is_some_and(|a| range.contains(&a)))
        .collect();
    let mut out = Vec::new();
    let mut at = range.start;
    let (mut si, mut gi) = (0, 0);
    // To the range's end (a span may run past it: its piece ends there).
    while at < range.end {
        while spans.get(si).is_some_and(|s| s.end <= at) {
            si += 1;
        }
        while globals
            .get(gi)
            .is_some_and(|g| g.address.is_none_or(|a| a < at))
        {
            gi += 1;
        }
        let span = spans.get(si);
        let global = globals.get(gi).map(|g| (g, g.address.unwrap_or(at)));
        let global_first = match (span, global) {
            (None, None) => break,
            (None, Some(_)) => true,
            (Some(_), None) => false,
            (Some(s), Some((_, a))) => a <= s.start.max(at),
        };
        if global_first {
            if let Some((g, a)) = global {
                out.push(Piece::Typed(g.key.clone()));
                at = at.max(a + g.size).min(range.end);
                gi += 1;
            }
            continue;
        }
        let Some(span) = span else {
            break;
        };
        let start = span.start.max(at);
        // What a typed global laid over it cuts (padding too: a user's
        // type is often laid over bytes the listing calls padding).
        let untyped = matches!(
            span.kind,
            SpanKind::Unexplored
                | SpanKind::Align
                | SpanKind::Fill { .. }
                | SpanKind::Uninitialised
        );
        let end = match global {
            Some((_, a)) if untyped && a < span.end => a,
            Some(_) | None => span.end.min(range.end),
        };
        match span.kind {
            SpanKind::Instruction { function: true } => {
                let entry = listing.function_of(start).map(|(_, e)| e);
                let mut end = end;
                let mut k = si + 1;
                while let Some(next) = spans.get(k)
                    && next.end <= range.end
                    && listing.function_of(next.start).map(|(_, e)| e) == entry
                    && global.is_none_or(|(_, a)| a >= next.end)
                {
                    end = next.end;
                    k += 1;
                }
                push_piece(
                    &mut out,
                    Piece::Function {
                        entry: entry.unwrap_or(start),
                        start,
                        end,
                        lines: lines.first_line(start)..lines.first_line(end),
                    },
                );
                at = end;
                si = k;
                continue;
            }
            SpanKind::Instruction { function: false }
            | SpanKind::String { .. }
            | SpanKind::Pointer { .. }
            | SpanKind::Import
            | SpanKind::Scalar { .. }
            | SpanKind::Values { .. }
            | SpanKind::Table => {
                push_piece(
                    &mut out,
                    Piece::Lines(lines.first_line(start)..lines.first_line(end)),
                );
            }
            // Padding shows as its bytes.
            SpanKind::Align | SpanKind::Fill { .. } | SpanKind::Unexplored => {
                match image.to_file(start) {
                    Some(f) => push_piece(&mut out, Piece::Bytes(f..f + (end - start))),
                    None => push_uninitialised(&mut out, listing, start..end),
                }
            }
            SpanKind::Uninitialised => push_uninitialised(&mut out, listing, start..end),
        }
        at = end;
    }
    out
}

/// Pushes the uninitialised addresses `range` as runs, but an item the
/// listing names in them (a `.bss` variable) as its lines, so a jump to
/// it lands on its name.
fn push_uninitialised(out: &mut Vec<Piece>, listing: &Listing, range: Range<u64>) {
    let lines = listing.lines();
    let last = lines.first_line(range.end);
    let mut at = range.start;
    let mut n = lines.first_line(range.start);
    while n < last {
        let Some(line) = listing.line(n) else {
            break;
        };
        let start = line.address;
        // The item's lines: up to the next item's.
        let next = lines.first_line(start.saturating_add(1)).min(last);
        if start >= at && listing.name(start).is_some() {
            let end = listing
                .line(next)
                .map_or(range.end, |l| l.address)
                .min(range.end);
            push_piece(out, Piece::Uninitialised(at..start));
            push_piece(out, Piece::Lines(n..next));
            at = end;
        }
        n = next.max(n + 1);
    }
    push_piece(out, Piece::Uninitialised(at..range.end));
}

/// Inserts into `items` the sections the file does not supply (`.bss`),
/// each after the mapped item before it.
fn insert_unsupplied(
    items: &mut Vec<Item>,
    image: &HexImage,
    listing: &Listing,
    globals: &[Global],
) {
    for (range, name) in image.sections() {
        if range.is_empty()
            || image.to_file(range.start).is_some()
            || !image.holds(Mode::Address, range.start)
        {
            continue;
        }
        let after = items
            .iter()
            .rposition(|i| i.address.as_ref().is_some_and(|a| a.start < range.start))
            .map_or(items.len(), |i| i + 1);
        let shown = after
            .checked_sub(1)
            .and_then(|i| items.get(i))
            .map_or(0, |i| i.file.end);
        items.insert(
            after,
            Item {
                kind: ItemKind::Section(Kind::Uninitialised),
                name: name.clone(),
                file: shown..shown,
                address: Some(range.clone()),
                pieces: mapped_pieces(listing, image, globals, range.clone()),
                strip: strip(listing, globals, range.clone()),
            },
        );
    }
}

/// The loops of `program`'s functions a block's header folds whole: each
/// natural loop's first block's address (its header's, or above it in a
/// loop whose test is at its bottom) to the end of its last, where its
/// blocks run on unbroken (no other block of its function between them).
pub fn loop_regions(program: &Program) -> BTreeMap<u64, u64> {
    let mut regions = BTreeMap::new();
    for (id, function) in program.functions.iter() {
        let loops = program.loops(id);
        if loops.is_empty() {
            continue;
        }
        let blocks = |ids: &[BlockId]| -> Vec<(u64, u64)> {
            let mut blocks: Vec<(u64, u64)> = ids
                .iter()
                .filter_map(|&b| program.blocks.get(b).map(|b| (b.start, b.end)))
                .collect();
            blocks.sort_unstable();
            blocks
        };
        let all = blocks(&function.blocks);
        for found in loops {
            let body = blocks(&found.blocks);
            let (Some(&(start, _)), Some(end)) = (body.first(), body.iter().map(|b| b.1).max())
            else {
                continue;
            };
            // Its function's blocks from its first to its end: its own.
            let between = all.partition_point(|b| b.0 < end) - all.partition_point(|b| b.0 < start);
            if between == body.len() {
                regions.insert(start, end);
            }
        }
    }
    regions
}

/// Pushes `piece`, merged into the last if they continue each other; an
/// empty one dropped.
fn push_piece(out: &mut Vec<Piece>, piece: Piece) {
    let merged = match (out.last_mut(), &piece) {
        (_, Piece::Lines(r) | Piece::Bytes(r) | Piece::Uninitialised(r)) if r.is_empty() => true,
        (Some(Piece::Lines(last)), Piece::Lines(r))
        | (Some(Piece::Bytes(last)), Piece::Bytes(r))
        | (Some(Piece::Uninitialised(last)), Piece::Uninitialised(r))
            if last.end == r.start =>
        {
            last.end = r.end;
            true
        }
        _ => false,
    };
    if !merged {
        out.push(piece);
    }
}

/// Whether the unified listing shows a line of `kind` (the cards stand
/// for the sections' and functions' headers, blank lines and separators
/// go, and an item's further cross-reference lines: its line shows them
/// all).
fn shows(kind: LineKind) -> bool {
    match kind {
        LineKind::Blank
        | LineKind::SegmentBorder
        | LineKind::SegmentType
        | LineKind::SegmentPermissions
        | LineKind::Banner
        | LineKind::Attributes
        | LineKind::Prototype
        | LineKind::Public
        | LineKind::Proc
        | LineKind::End
        | LineKind::Separator
        | LineKind::Xref => false,
        LineKind::Frame
        | LineKind::Label
        | LineKind::Preview
        | LineKind::Instruction
        | LineKind::Data
        | LineKind::Comment => true,
    }
}

/// The kind of row `row` of item `item`, for the overview: a line's by its
/// item (data by its span), a tree's by its item (a header's, else typed
/// data), bytes by their section; none for a card.
fn row_kind(item: &Item, row: &Row, listing: &Listing) -> Option<Kind> {
    let section = match item.kind {
        ItemKind::Header(_) => Kind::Header,
        ItemKind::Section(kind) => kind,
        ItemKind::Outside => Kind::Other,
    };
    Some(match &row.kind {
        RowKind::Card { .. } | RowKind::Spacer => return None,
        RowKind::Block { .. } => Kind::Code,
        RowKind::Line(n) => {
            let line = listing.line(*n)?;
            match line.item {
                LineItem::Function => Kind::Code,
                LineItem::Code => Kind::LooseCode,
                LineItem::Unexplored => Kind::Unexplored,
                LineItem::Data => listing
                    .lines()
                    .spans(line.address..line.address + 1)
                    .first()
                    .map_or(Kind::Value, |s| span_kind(s).0),
            }
        }
        RowKind::Field(_) if section == Kind::Header || section == Kind::Table => section,
        RowKind::Field(_) => Kind::Value,
        RowKind::Hex(_) | RowKind::Run { .. } | RowKind::Bytes(_) => match section {
            Kind::Section => Kind::Unexplored,
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
            | Kind::Gap => section,
        },
        RowKind::Uninitialised(_) => Kind::Uninitialised,
    })
}

/// The rows of listing lines `lines`, `depth` deep.
fn push_lines(out: &mut Vec<Row>, listing: &Listing, lines: Range<u64>, depth: u8) {
    for n in lines {
        if listing.line(n).is_some_and(|l| shows(l.kind)) {
            out.push(Row {
                kind: RowKind::Line(n),
                depth,
            });
        }
    }
}

/// The rows of a function's listing lines `lines` (2 deep): each label a
/// block's header, the block's lines (to the next label) under it unless
/// it is folded.
fn push_function(
    out: &mut Vec<Row>,
    pane: &UnifiedPane,
    (listing, loops): (&Listing, &BTreeMap<u64, u64>),
    lines: Range<u64>,
) {
    let mut folded = false;
    // A folded loop's end: its blocks' lines (their labels too) hidden.
    let mut folded_loop: Option<u64> = None;
    for n in lines {
        let Some(line) = listing.line(n) else {
            continue;
        };
        if let Some(end) = folded_loop {
            if line.address < end {
                continue;
            }
            folded_loop = None;
            folded = false;
        }
        if line.kind == LineKind::Label {
            let open = pane.is_open(Fold::Block(line.address), true);
            out.push(Row {
                kind: RowKind::Block { line: n, open },
                depth: 2,
            });
            folded = !open;
            folded_loop = loops.get(&line.address).copied().filter(|_| !open);
        } else if !folded && shows(line.kind) {
            out.push(Row {
                kind: RowKind::Line(n),
                depth: 2,
            });
        }
    }
}

/// The rows of `key`'s tree under its card (`depth` deep): its children,
/// if it is expanded, depth first.
fn push_tree(out: &mut Vec<Row>, tree: &StructTree, overlays: &[Overlay], key: &Key, depth: u8) {
    for line in tree.lines_under(overlays, key).into_iter().skip(1) {
        let below = u8::try_from(line.depth).unwrap_or(u8::MAX);
        out.push(Row {
            kind: RowKind::Field(line),
            depth: depth.saturating_add(below),
        });
    }
}

/// The rows of untyped bytes `range` of `file`, `depth` deep: hex rows on
/// 16-byte boundaries, a run of one value of [`RUN`] bytes or more one
/// row; one row for all with `hex` off.
fn push_bytes(out: &mut Vec<Row>, file: &[u8], range: Range<u64>, depth: u8, hex: bool) {
    if range.is_empty() {
        return;
    }
    if !hex {
        out.push(Row {
            kind: RowKind::Bytes(range),
            depth,
        });
        return;
    }
    let byte = |at: u64| usize::try_from(at).ok().and_then(|i| file.get(i)).copied();
    let mut plain = range.start;
    let mut at = range.start;
    while at < range.end {
        let value = byte(at);
        let mut end = at + 1;
        while end < range.end && byte(end) == value {
            end += 1;
        }
        if end - at >= RUN
            && let Some(value) = value
        {
            push_hex(out, plain..at, depth);
            out.push(Row {
                kind: RowKind::Run {
                    file: at..end,
                    byte: value,
                },
                depth,
            });
            plain = end;
        }
        at = end;
    }
    push_hex(out, plain..range.end, depth);
}

/// Hex rows of `range`, [`HEX_ROW`] bytes each on their boundaries (the
/// first from the range's first byte to the next).
fn push_hex(out: &mut Vec<Row>, range: Range<u64>, depth: u8) {
    let mut row = range.start;
    while row < range.end {
        let next = ((row / HEX_ROW + 1) * HEX_ROW).min(range.end);
        out.push(Row {
            kind: RowKind::Hex(row..next),
            depth,
        });
        row = next;
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests fail loudly"
    )]

    use binbun::Database;
    use binbun::analysis::Seeds;
    use binbun_loader::Image;

    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(&path).unwrap()
    }

    /// The fixture's document and listing, its header overlays the
    /// overlays.
    fn document(data: &[u8]) -> (Document, Listing, HexImage, Vec<Overlay>) {
        let image = Image::parse(data).unwrap();
        let db = Database::new(&image, Seeds::ALL).unwrap();
        let listing = Listing::build(&db, &crate::listing::Options::default());
        let hex = HexImage::new(data, &image);
        let overlays = hex.headers().to_vec();
        let loops = Arc::new(loop_regions(db.program()));
        let doc = Document::build(&hex, &listing, &overlays, loops);
        (doc, listing, hex, overlays)
    }

    fn item<'a>(doc: &'a Document, name: &str) -> (usize, &'a Item) {
        doc.items
            .iter()
            .enumerate()
            .find(|(_, i)| i.name == name)
            .unwrap()
    }

    /// The inputs of a flattening.
    fn inputs<'a>(overlays: &'a [Overlay], listing: &'a Listing, file: &'a [u8]) -> Inputs<'a> {
        Inputs {
            overlays,
            listing,
            file,
        }
    }

    /// The whole file, in order: the ELF header and the program headers
    /// as their trees, the sections, the section headers at the end; the
    /// items cover the file without overlapping.
    #[test]
    fn the_document_covers_the_file_in_order() {
        let data = fixture("program-x86_64.elf");
        let (doc, _, hex, overlays) = document(&data);
        let first = &doc.items[0];
        assert_eq!(first.name, "ELF header");
        // The file's typed tables are items of their own: their trees.
        for table in [".dynsym", ".symtab", ".dynamic", ".rela.dyn"] {
            let (_, item) = item(&doc, table);
            assert!(
                matches!(item.kind, ItemKind::Header(_)),
                "{table}: {:?}",
                item.kind
            );
        }
        let ItemKind::Header(key) = &first.kind else {
            panic!("{:?}", first.kind)
        };
        assert_eq!(hex_tree::resolve(&overlays, key).unwrap().name, "ehdr");
        assert!(matches!(doc.items[1].kind, ItemKind::Header(_)));
        let last = doc.items.iter().rfind(|i| !i.file.is_empty()).unwrap();
        assert_eq!(last.file.end, hex.file_len());
        let mut end = 0;
        for i in doc.items.iter().filter(|i| !i.file.is_empty()) {
            assert_eq!(i.file.start, end, "{} starts where the last ended", i.name);
            end = i.file.end;
        }
        // `.bss` is after the mapped item before it, holding no file bytes.
        let (b, bss) = item(&doc, ".bss");
        assert!(bss.file.is_empty());
        let before = doc.items[..b]
            .iter()
            .rfind(|i| i.address.is_some())
            .unwrap();
        assert!(before.address.as_ref().unwrap().start < bss.address.as_ref().unwrap().start);
        assert!(
            bss.pieces
                .iter()
                .all(|p| matches!(p, Piece::Uninitialised(_) | Piece::Lines(_)))
        );
        // A mapped section's strip says what it holds where: `.text` its
        // functions' code, `.rodata` strings among its values; the
        // unmapped and the headers have none.
        let (_, text) = item(&doc, ".text");
        assert_eq!(text.strip.len(), STRIP);
        let code = text.strip.iter().filter(|&&k| k == Kind::Code).count();
        assert!(code > STRIP / 2, "{:?}", text.strip);
        let (_, rodata) = item(&doc, ".rodata");
        assert!(rodata.strip.contains(&Kind::String), "{:?}", rodata.strip);
        assert_eq!(item(&doc, ".symtab").1.strip, []);
        assert_eq!(doc.items[0].strip, []);
        // Padding between functions is bytes, not `align` lines.
        assert!(text.pieces.iter().any(|p| matches!(p, Piece::Bytes(_))));
    }

    /// A Mach-O file's (a universal file's `x86_64` slice, as a session
    /// holds it): its load commands and sections cover it in order, its
    /// code its functions.
    #[test]
    fn a_mach_o_document_covers_its_slice_in_order() {
        let data = fixture("program-universal.macho");
        let slice = Image::parse(&data).unwrap().slice.unwrap();
        let start = usize::try_from(slice.offset).unwrap();
        let bytes = &data[start..start + usize::try_from(slice.size).unwrap()];
        let (doc, listing, hex, overlays) = document(bytes);
        let mut end = 0;
        for i in doc.items.iter().filter(|i| !i.file.is_empty()) {
            assert_eq!(i.file.start, end, "{} starts where the last ended", i.name);
            end = i.file.end;
        }
        assert_eq!(end, hex.file_len());
        let entries: Vec<u64> = doc
            .items
            .iter()
            .flat_map(|i| &i.pieces)
            .filter_map(|p| match p {
                Piece::Function { entry, start, .. } if entry == start => Some(*entry),
                Piece::Function { .. }
                | Piece::Lines(_)
                | Piece::Typed(_)
                | Piece::Bytes(_)
                | Piece::Uninitialised(_) => None,
            })
            .collect();
        assert!(entries.len() >= 5, "{entries:x?}");
        let flat = doc.flatten(&UnifiedPane::default(), &inputs(&overlays, &listing, bytes));
        for entry in entries {
            let row = doc.row_of(&flat, entry, &listing, &hex, &overlays).unwrap();
            let at = doc.address(&flat.rows[row], &listing, &hex, &overlays);
            assert_eq!(at, Some(entry), "{entry:#x}");
        }
    }

    /// A type laid over padding (Apply Type) is a typed piece where it
    /// starts, the padding's other bytes still bytes after it.
    #[test]
    fn a_type_laid_over_padding_is_its_piece() {
        use crate::hex::{Anchor, user_overlay};
        use crate::hex_types::TypeSet;

        let data = fixture("program-x86_64.elf");
        let (doc, listing, hex, mut overlays) = document(&data);
        let (_, text) = item(&doc, ".text");
        let pad = listing
            .lines()
            .spans(text.address.clone().unwrap())
            .into_iter()
            .find(|s| s.kind == SpanKind::Align && s.end - s.start > 2)
            .unwrap();
        let layout = TypeSet::builtin(hex.model()).apply("uint16_t").unwrap();
        overlays.push(user_overlay(Anchor::Address(pad.start), layout, "uint16_t"));
        let key = Key::root(overlays.len() - 1);
        let doc = Document::build(&hex, &listing, &overlays, Arc::default());
        let (_, text) = item(&doc, ".text");
        let at = text
            .pieces
            .iter()
            .position(|p| matches!(p, Piece::Typed(k) if *k == key))
            .expect("the type is a piece");
        assert_eq!(
            Document::piece_address(&text.pieces[at], &hex, &overlays),
            Some(pad.start)
        );
        let rest = pad.end - pad.start - 2;
        assert!(
            matches!(&text.pieces[at + 1], Piece::Bytes(r) if r.end - r.start == rest),
            "{:?}",
            text.pieces[at + 1]
        );
    }

    /// `.text` holds its functions as pieces, each its own lines; folding
    /// a function leaves its card, and the cursor's address finds the card.
    #[test]
    fn a_function_is_a_card_over_its_lines() {
        let data = fixture("program-x86_64.elf");
        let (doc, listing, hex, overlays) = document(&data);
        let (t, text) = item(&doc, ".text");
        let (p, piece) = text
            .pieces
            .iter()
            .enumerate()
            .find(|(_, p)| matches!(p, Piece::Function { start: 0x11d0, .. }))
            .unwrap();
        let Piece::Function { entry, lines, .. } = piece else {
            unreachable!()
        };
        assert_eq!(*entry, 0x11d0);
        assert!(
            lines
                .clone()
                .any(|n| listing.line(n).unwrap().kind == LineKind::Instruction)
        );
        assert!(lines.clone().all(|n| {
            listing
                .function_of(listing.line(n).unwrap().address)
                .is_some()
                || listing.line(n).unwrap().kind == LineKind::Blank
        }));
        let mut pane = UnifiedPane::default();
        let flat = doc.flatten(&pane, &inputs(&overlays, &listing, &data));
        let at = doc
            .row_of(&flat, 0x11d0, &listing, &hex, &overlays)
            .unwrap();
        let RowKind::Line(n) = flat.rows[at].kind else {
            panic!("{:?}", flat.rows[at])
        };
        let line = listing.line(n).unwrap();
        assert_eq!((line.address, line.kind), (0x11d0, LineKind::Instruction));
        assert_eq!(flat.rows[at].depth, 2);
        // No banner, prototype or `proc` line under the card.
        assert!(flat.rows.iter().all(|r| {
            let RowKind::Line(n) = r.kind else {
                return true;
            };
            shows(listing.line(n).unwrap().kind)
        }));
        doc.toggle(&mut pane, t, Some(p));
        let folded = doc.flatten(&pane, &inputs(&overlays, &listing, &data));
        assert!(folded.len() < flat.len());
        let at = doc
            .row_of(&folded, 0x11d0, &listing, &hex, &overlays)
            .unwrap();
        assert_eq!(
            folded.rows[at].kind,
            RowKind::Card {
                item: t,
                piece: Some(p),
                open: false
            }
        );
        // An address inside it finds the card too.
        let at = doc
            .row_of(&folded, 0x11d4, &listing, &hex, &overlays)
            .unwrap();
        assert!(matches!(folded.rows[at].kind, RowKind::Card { piece: Some(q), .. } if q == p));
    }

    /// A label inside a function heads its block: no label line, a block
    /// row; folded, the block's lines go, and an address in them finds
    /// the block's row. Scrolled to a line in a block, the section's
    /// card, the function's and the block's header are pinned, outermost
    /// first.
    #[test]
    fn a_label_heads_a_block_that_folds_and_pins() {
        let data = fixture("program-x86_64.elf");
        let (doc, listing, hex, overlays) = document(&data);
        let mut pane = UnifiedPane::default();
        let flat = doc.flatten(&pane, &inputs(&overlays, &listing, &data));
        assert!(flat.rows.iter().all(|r| {
            let RowKind::Line(n) = r.kind else {
                return true;
            };
            r.depth < 2 || listing.line(n).unwrap().kind != LineKind::Label
        }));
        let (b, label) = flat
            .rows
            .iter()
            .enumerate()
            .find_map(|(k, r)| {
                let RowKind::Block { line, open: true } = r.kind else {
                    return None;
                };
                Some((k, listing.line(line).unwrap()))
            })
            .unwrap();
        let RowKind::Line(inside) = flat.rows[b + 1].kind else {
            panic!("{:?}", flat.rows[b + 1])
        };
        let inside = listing.line(inside).unwrap().address;
        pane.flip(Fold::Block(label.address));
        let folded = doc.flatten(&pane, &inputs(&overlays, &listing, &data));
        assert!(folded.len() < flat.len());
        let at = doc
            .row_of(&folded, inside, &listing, &hex, &overlays)
            .unwrap();
        assert!(matches!(
            folded.rows[at].kind,
            RowKind::Block { open: false, .. }
        ));

        let pinned = flat.sticky(b + 1);
        assert_eq!(pinned.len(), 3, "{pinned:?}");
        assert!(matches!(
            flat.rows[pinned[0]].kind,
            RowKind::Card { piece: None, .. }
        ));
        assert!(matches!(
            flat.rows[pinned[1]].kind,
            RowKind::Card { piece: Some(_), .. }
        ));
        assert_eq!(pinned[2], b);
    }

    /// Scrolled to just above a function's card (its spacer under the
    /// pinned stack), the previous function's header is not pinned over
    /// it; inside, the card is.
    #[test]
    fn pinned_headers_make_way_for_the_next_card() {
        let data = fixture("program-x86_64.elf");
        let (doc, listing, _, overlays) = document(&data);
        let flat = doc.flatten(&UnifiedPane::default(), &inputs(&overlays, &listing, &data));
        let card = (2..flat.len())
            .find(|&k| {
                matches!(flat.rows[k].kind, RowKind::Card { piece: Some(_), .. })
                    && flat.rows[k - 1].kind == RowKind::Spacer
                    && matches!(flat.rows[k - 2].kind, RowKind::Line(_))
                    && matches!(flat.rows[k + 1].kind, RowKind::Line(_))
                    && matches!(flat.rows[k + 2].kind, RowKind::Line(_))
                    && flat.sticky(k - 2).len() > 1
            })
            .unwrap();
        let section = flat.sticky(card)[0];
        assert_eq!(flat.pinned(card - 2), vec![section]);
        assert_eq!(flat.pinned(card + 1).get(..2), Some(&[section, card][..]));
    }

    /// With the spacers between functions, an address still finds its
    /// row: each function's entry its first instruction.
    #[test]
    fn every_function_is_found_at_its_entry() {
        let data = fixture("program-x86_64.elf");
        let (doc, listing, hex, overlays) = document(&data);
        let flat = doc.flatten(&UnifiedPane::default(), &inputs(&overlays, &listing, &data));
        let entries: Vec<u64> = flat
            .rows
            .iter()
            .filter_map(|r| {
                let RowKind::Card {
                    item,
                    piece: Some(p),
                    ..
                } = r.kind
                else {
                    return None;
                };
                let Piece::Function { start, .. } = doc.items[item].pieces[p] else {
                    return None;
                };
                Some(start)
            })
            .collect();
        assert!(entries.len() > 5, "{entries:x?}");
        assert!(flat.rows.iter().any(|r| r.kind == RowKind::Spacer));
        for entry in entries {
            let at = doc.row_of(&flat, entry, &listing, &hex, &overlays).unwrap();
            let row = &flat.rows[at];
            assert!(matches!(row.kind, RowKind::Line(_)), "{entry:#x}: {row:?}");
            assert_eq!(doc.address(row, &listing, &hex, &overlays), Some(entry));
        }
    }

    /// Wherever the cursor comes from, a jump, a step and the sync group
    /// each put its row on screen below the headers pinned at the top; the
    /// rows made again keep it as many rows from the top as it was.
    #[test]
    fn a_landing_puts_its_row_in_sight_below_the_pinned_headers() {
        let data = fixture("program-x86_64.elf");
        let (doc, listing, _, overlays) = document(&data);
        let mut pane = UnifiedPane::default();
        let flat = doc.flatten(&pane, &inputs(&overlays, &listing, &data));
        let visible = 20u8;
        let screen = |pane: &UnifiedPane| {
            let top = usize::try_from(pane.scroll.anchor.line).unwrap();
            (pane.cursor - top, flat.pinned(top).len())
        };
        let rows: Vec<usize> = (0..flat.len())
            .filter(|&k| flat.rows[k].kind != RowKind::Spacer)
            .collect();
        assert!(rows.len() > 100, "{}", rows.len());
        for how in [Landing::Jump, Landing::Step, Landing::Follow] {
            for &row in &rows {
                let far = if row > flat.len() / 2 {
                    0
                } else {
                    flat.len() - 1
                };
                pane.land(&flat, far, Landing::Jump, visible.into());
                pane.land(&flat, row, how, visible.into());
                assert_eq!(pane.cursor, row);
                let (at, pinned) = screen(&pane);
                assert!(
                    pinned <= at && at < visible.into(),
                    "{how:?} to {row} ({:?}): row {at} on screen, {pinned} pinned",
                    flat.rows[row].kind
                );
            }
        }
        for &row in rows.iter().filter(|&&k| k >= 5 && k + 20 < flat.len()) {
            pane.land(&flat, row, Landing::Kept(5), visible.into());
            assert_eq!(screen(&pane).0, 5, "kept {row}");
        }
    }

    /// The sync seam, both ways: a row of an address stands for a listing
    /// line at it (a line's row for its own line), and the address finds
    /// a row holding it again; a row of none stands for no line.
    #[test]
    fn every_row_and_its_listing_line_find_each_other() {
        let data = fixture("program-x86_64.elf");
        let (doc, listing, hex, overlays) = document(&data);
        let flat = doc.flatten(&UnifiedPane::default(), &inputs(&overlays, &listing, &data));
        let mut checked = 0;
        for row in &flat.rows {
            let line = doc.listing_line(row, &listing, &hex, &overlays);
            let Some(address) = doc.address(row, &listing, &hex, &overlays) else {
                assert_eq!(line, None, "{row:?}");
                continue;
            };
            let n = line.unwrap();
            let at = listing.line(n).unwrap().address;
            match row.kind {
                RowKind::Line(own) | RowKind::Block { line: own, .. } => assert_eq!(n, own),
                RowKind::Card { .. }
                | RowKind::Field(_)
                | RowKind::Hex(_)
                | RowKind::Run { .. }
                | RowKind::Bytes(_)
                | RowKind::Uninitialised(_)
                | RowKind::Spacer => assert!(at <= address, "{row:?}: line {n} at {at:#x}"),
            }
            let found = doc.row_of(&flat, address, &listing, &hex, &overlays);
            let found = found.unwrap_or_else(|| panic!("{address:#x} ({row:?}) finds no row"));
            let there = doc.address(&flat.rows[found], &listing, &hex, &overlays);
            assert!(
                there.is_some_and(|a| a <= address),
                "{address:#x}: {there:x?}"
            );
            checked += 1;
        }
        assert!(checked > 100, "{checked}");
    }

    /// A variable the listing names in `.bss` is a line of its own, not
    /// lost in a run of uninitialised bytes.
    #[test]
    fn named_uninitialised_variables_have_their_lines() {
        let data = fixture("program-x86_64.elf");
        let (doc, listing, hex, overlays) = document(&data);
        let flat = doc.flatten(&UnifiedPane::default(), &inputs(&overlays, &listing, &data));
        let lines = listing.lines();
        for r in &flat.rows {
            let RowKind::Uninitialised(run) = &r.kind else {
                continue;
            };
            for n in lines.first_line(run.start)..lines.first_line(run.end) {
                let a = listing.line(n).unwrap().address;
                assert!(listing.name(a).is_none(), "{a:#x} named in {run:x?}");
            }
        }
        let completed = 0x4028;
        assert_eq!(listing.name(completed), Some("completed.0"));
        let at = doc
            .row_of(&flat, completed, &listing, &hex, &overlays)
            .unwrap();
        let RowKind::Line(n) = flat.rows[at].kind else {
            panic!("{:?}", flat.rows[at]);
        };
        assert_eq!(listing.line(n).unwrap().address, completed);
    }

    /// A loop's header folds the loop whole: its blocks' labels and lines
    /// go under it, and a jump into it lands on the header.
    #[test]
    fn a_loop_folds_whole_from_its_header() {
        let data = fixture("program-x86_64.elf");
        let (doc, listing, hex, overlays) = document(&data);
        let mut pane = UnifiedPane::default();
        let flat = doc.flatten(&pane, &inputs(&overlays, &listing, &data));
        let address = |r: &Row| doc.address(r, &listing, &hex, &overlays);
        let inside = |flat: &Flat, (start, end): (u64, u64)| {
            flat.rows
                .iter()
                .filter(|r| address(r).is_some_and(|a| (start..end).contains(&a)))
                .count()
        };
        // A loop whose header is a label, with lines under it.
        let (start, end) = doc
            .loops
            .iter()
            .map(|(&s, &e)| (s, e))
            .find(|&(s, e)| {
                let header = flat
                    .rows
                    .iter()
                    .filter(|r| matches!(r.kind, RowKind::Block { .. }))
                    .find_map(|r| address(r).filter(|a| (s..e).contains(a)));
                header == Some(s) && inside(&flat, (s, e)) > 2
            })
            .unwrap();
        let open = inside(&flat, (start, end));
        pane.flip(Fold::Block(start));
        let folded = doc.flatten(&pane, &inputs(&overlays, &listing, &data));
        assert_eq!(inside(&folded, (start, end)), 1, "only the header");
        assert_eq!(flat.len() - folded.len(), open - 1);
        let last = end - 1;
        let at = doc
            .row_of(&folded, last, &listing, &hex, &overlays)
            .unwrap();
        assert!(matches!(
            folded.rows[at].kind,
            RowKind::Block { open: false, .. }
        ));
        assert_eq!(address(&folded.rows[at]), Some(start));
    }

    /// A tab's expanded rows are kept by their overlays' places: shown
    /// again with the overlays in another order (globals laid out since),
    /// the same rows are expanded, once their overlays are there.
    #[test]
    fn expanded_rows_follow_their_overlays_not_their_indices() {
        let data = fixture("program-x86_64.elf");
        let (_, _, _, overlays) = document(&data);
        let header = overlays[0].clone();
        let row = Key {
            root: 0,
            steps: vec![Step::Member(0)],
        };
        let mut left = UnifiedPane::default();
        left.tree.toggle(&row);
        let kept = left.view(&overlays);
        assert_eq!(kept.expanded.len(), 1);

        let mut back = UnifiedPane::default();
        back.set_view(&kept);
        assert!(!back.expand_pending(&[]), "no overlay yet");
        let mut other = header.clone();
        other.anchor = Anchor::Address(0x1234);
        let now = [other, header];
        assert!(back.expand_pending(&now));
        let moved = Key { root: 1, ..row };
        assert!(back.tree.is_expanded(&moved));
        assert_eq!(back.view(&now), kept);
    }

    /// The headers open into their fields; the structure layer off leaves
    /// only the mapped sections; the hex layer off makes each run of
    /// untyped bytes one row.
    #[test]
    fn layers_and_trees_change_the_rows() {
        let data = fixture("program-x86_64.elf");
        let (doc, listing, _, overlays) = document(&data);
        let mut pane = UnifiedPane::default();
        let flat = doc.flatten(&pane, &inputs(&overlays, &listing, &data));
        assert_eq!(
            flat.rows[0].kind,
            RowKind::Card {
                item: 0,
                piece: None,
                open: false
            }
        );
        doc.toggle(&mut pane, 0, None);
        let open = doc.flatten(&pane, &inputs(&overlays, &listing, &data));
        let fields: Vec<String> = open.rows[1..]
            .iter()
            .map_while(|r| match &r.kind {
                RowKind::Field(line) => Some(hex_tree::resolve(&overlays, &line.key).unwrap().name),
                RowKind::Card { .. }
                | RowKind::Line(_)
                | RowKind::Block { .. }
                | RowKind::Hex(_)
                | RowKind::Run { .. }
                | RowKind::Bytes(_)
                | RowKind::Uninitialised(_)
                | RowKind::Spacer => None,
            })
            .collect();
        assert_eq!(fields.first().map(String::as_str), Some("e_ident"));
        assert!(fields.iter().any(|f| f == "e_shnum"));
        assert_eq!(open.rows[1].depth, 1);

        pane.layers.structure = false;
        pane.flat = None;
        let mapped = doc.flatten(&pane, &inputs(&overlays, &listing, &data));
        for r in &mapped.rows {
            if let RowKind::Card {
                item, piece: None, ..
            } = r.kind
            {
                let item = &doc.items[item];
                assert!(item.address.is_some(), "{}", item.name);
                assert!(!matches!(item.kind, ItemKind::Header(_)), "{}", item.name);
            }
        }

        // An unmapped section of raw bytes (the string table) opened: its
        // hex rows, of [`HEX_ROW`] bytes within their boundaries.
        let mut pane = UnifiedPane::default();
        let (s, strtab) = item(&doc, ".strtab");
        let strtab = strtab.file.clone();
        doc.toggle(&mut pane, s, None);
        let flat = doc.flatten(&pane, &inputs(&overlays, &listing, &data));
        let hex_rows: Vec<&Range<u64>> = flat
            .rows
            .iter()
            .filter_map(|r| {
                let RowKind::Hex(range) = &r.kind else {
                    return None;
                };
                strtab.contains(&range.start).then_some(range)
            })
            .collect();
        assert!(hex_rows.len() > 10, "{} rows", hex_rows.len());
        assert!(
            hex_rows
                .iter()
                .all(|r| r.end - r.start <= HEX_ROW && (r.end - 1) / HEX_ROW == r.start / HEX_ROW)
        );
        pane.layers.hex = false;
        let flat = doc.flatten(&pane, &inputs(&overlays, &listing, &data));
        assert!(flat.rows.iter().all(|r| !matches!(r.kind, RowKind::Hex(_))));
        assert!(
            flat.rows
                .iter()
                .any(|r| matches!(r.kind, RowKind::Bytes(_)))
        );
    }

    /// A run of one value of [`RUN`] bytes or more is one row; shorter
    /// runs stay hex rows, of [`HEX_ROW`] bytes on their boundaries, the
    /// first from the first byte.
    #[test]
    fn long_runs_of_one_value_are_one_row() {
        let mut file = vec![1u8; 8];
        file.extend([0; 100]);
        file.extend([2; 10]);
        let mut out = Vec::new();
        push_bytes(&mut out, &file, 0..118, 0, true);
        let kinds: Vec<RowKind> = out.into_iter().map(|r| r.kind).collect();
        assert_eq!(
            kinds,
            [
                RowKind::Hex(0..8),
                RowKind::Run {
                    file: 8..108,
                    byte: 0
                },
                RowKind::Hex(108..112),
                RowKind::Hex(112..118),
            ]
        );
        let mut out = Vec::new();
        push_bytes(&mut out, &(0..64).collect::<Vec<u8>>(), 3..29, 0, true);
        let kinds: Vec<RowKind> = out.into_iter().map(|r| r.kind).collect();
        assert_eq!(
            kinds,
            [
                RowKind::Hex(3..8),
                RowKind::Hex(8..16),
                RowKind::Hex(16..24),
                RowKind::Hex(24..29),
            ]
        );
    }
}
