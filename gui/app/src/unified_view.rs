//! The unified listing in a listing pane (an experiment:
//! `research/unified-listing-design.md`): the whole file as one document
//! ([`binbun_gui_view::unified`]), each item under a card (a header, a
//! section, a function, a typed global, untyped bytes) that its chevron, a
//! double-click, Enter, Left and Right fold and open; its layers (the
//! instructions' bytes, untyped bytes as hex, the file's structure) in the
//! toolbar. The cursor is a row; the sync group follows its address.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::ops::RangeInclusive;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use binbun::Database;
use binbun::references::{Kind as RefKind, Reference};
use binbun_gui_view::CTokenKind;
use binbun_gui_view::cdoc::CDocument;
use binbun_gui_view::commands::Command;
use binbun_gui_view::hex::{CopyFormat, HexImage, Kind, Mode, Overlay, Source};
use binbun_gui_view::hex_tree::{self, Key};
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::listing::{Arrow, LineKind, Listing, Role, Token};
use binbun_gui_view::selection::MOST_COPIED;
use binbun_gui_view::settype::TypeField;
use binbun_gui_view::unified::{
    Document, Flat, Fold, Inputs, Landing, Layers, Piece, Row, RowKind, UnifiedView, loop_regions,
};
use gpui_kit::assets::IconName;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, FontWeight, KeyDownEvent, MouseButton, MouseDownEvent, MouseMoveEvent,
    Pixels, Point, ScrollEvent, Stateful, StyledText, TextRun, Window, div, point, px,
};

use crate::arrows::{self, GAP, Geometry, Hit, LABEL_SCALE, LANE, StubStyle};
use crate::context_menu::OwnItem;
use crate::hex_view::kind_color;
use crate::highlight::Highlight;
use crate::icons::icon;
use crate::listing_view::{SCROLLBAR, highlightable, peekable, token_at};
use crate::panes::measured;
use crate::search_view::marked;
use crate::tabs::name_click;
use crate::theme::{hsla, over, solid, with_alpha};
use crate::type_field::Place;
use crate::unified_rows::{Header, RowView, row_text};
use crate::workspace::{ICON, ICON_BUTTON, Link, TabKind, Workspace, f, rows_in};

/// The document as last built, and what from.
#[derive(Default)]
pub struct UnifiedUi {
    built: Option<Built>,
    /// The decompiler's signatures of functions, from printed C (a
    /// function's own definition's line, a caller's declaration of it):
    /// the document and its line, by entry.
    signatures: HashMap<u64, (Arc<CDocument>, usize)>,
    /// The documents read for signatures, the latest last.
    harvested: Vec<Arc<CDocument>>,
    /// Each pane's cursor's row on screen (rows from the top) as it was
    /// before the document was made again, for its cursor found again.
    kept: HashMap<PaneId, u64>,
    /// Where the type on a pane's cursor row was drawn last (the pane's
    /// pixels from its left): the pane, the row, the x.
    type_x: Cell<Option<(PaneId, usize, f32)>>,
    /// The loops the headers fold, and the analysis they are of (the
    /// control flow is the same until it is analysed again).
    loops: Option<(u64, Arc<BTreeMap<u64, u64>>)>,
    /// Each pane's arrow stubs as last drawn, for the pointer.
    stubs: RefCell<HashMap<PaneId, Stubs>>,
    /// The tree rows' columns by their parent row: its children's widest
    /// name and type (for the document as built).
    columns: RefCell<HashMap<Key, (usize, usize)>>,
}

/// A pane's arrow stubs as drawn: where its gutter starts (the pane's
/// pixels), the arrows' regions there, and each stub's arrow's ends'
/// addresses by its rows.
#[derive(Default)]
struct Stubs {
    left: f32,
    hits: Vec<Hit>,
    ends: HashMap<(u64, u64), (u64, u64)>,
}

/// A document and its sources.
struct Built {
    listing: Arc<Listing>,
    image: Arc<HexImage>,
    overlays: Arc<Vec<Overlay>>,
    doc: Arc<Document>,
}

/// The document and its sources, as one.
pub type Sources = (
    Arc<Document>,
    Arc<Listing>,
    Arc<HexImage>,
    Arc<Vec<Overlay>>,
);

/// A text part: its text, colour, and whether it is bold.
pub type Part = (String, u32, bool);

/// The most bytes of an instruction the bytes layer shows.
pub const BYTES_SHOWN: usize = 8;
/// The most lines of the C a signature is read from.
const SIGNATURE_LINES: usize = 32;
/// The widest a tree's name column and type column grow to fit its rows;
/// a longer name or type pushes its own row on.
pub const FIELD_NAME_MOST: usize = 28;
pub const FIELD_TYPE_MOST: usize = 24;

/// A section card's strip's width.
const STRIP_WIDTH: f32 = 180.0;
/// The overview's width, left of the scrollbar.
const MINIMAP: f32 = 10.0;
/// How long the row a jump lands on is lit, fading.
const LANDING: Duration = Duration::from_millis(900);
/// How many documents' declarations are remembered as read.
const HARVESTED: usize = 16;

/// Where a row's parts go, from the pane's left edge: the fold chevrons,
/// the address, the bytes, the marks (a card's symbol, the branch
/// arrows) and the text.
#[derive(Clone, Copy, Debug)]
pub struct Columns {
    pub fold: f32,
    pub address: f32,
    pub bytes: f32,
    pub marks: f32,
    pub text: f32,
    /// Whether the bytes column shows bytes.
    pub shows_bytes: bool,
    /// A character's width.
    pub cw: f32,
}

/// Whether C line `text` is a statement of control (`if`, a loop, a
/// `switch`, a `return`, a `goto`, a `case`, an `else`).
fn is_control(text: &str) -> bool {
    let text = text.trim_start().trim_start_matches("} ");
    [
        "if", "while", "for", "do", "switch", "return", "goto", "break", "continue", "case",
        "default", "else",
    ]
    .iter()
    .any(|k| {
        text.strip_prefix(k)
            .is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
    })
}

/// A cross-reference as a chip says it.
#[derive(Clone)]
pub struct XrefChip {
    /// Where it is made.
    from: u64,
    /// That place, named (`main+60`).
    source: String,
    /// Its direction and kind (`↓j`).
    mark: String,
    /// Whether code makes it (a call or a jump).
    code: bool,
}

/// The lines of `doc` a declaration starting on line `line` takes: to the
/// one closing its parameters' `(` (the printer wraps a long list), at
/// most [`SIGNATURE_LINES`].
fn signature_lines(doc: &CDocument, line: usize) -> std::ops::Range<usize> {
    let mut depth = 0i64;
    let mut end = line;
    while end < doc.lines.len() && end < line + SIGNATURE_LINES {
        for c in doc.line_text(end).chars() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
        }
        end += 1;
        if depth <= 0 {
            break;
        }
    }
    line..end
}

/// Row `row` of `flat`, or past the spacers there (up, or down) to the
/// row beyond them: a spacer is no place for the cursor.
fn past_spacers(flat: &Flat, mut row: usize, up: bool) -> usize {
    while flat
        .rows
        .get(row)
        .is_some_and(|r| r.kind == RowKind::Spacer)
    {
        match (up, row.checked_sub(1)) {
            (true, Some(above)) => row = above,
            _ if row + 1 < flat.len() => row += 1,
            _ => break,
        }
    }
    row
}

/// Where a reference at `address` is from: a function's place, else the
/// data object holding it (`shaders+10`), else the listing's words.
fn source_of(db: &Database<'_>, listing: &Listing, address: u64) -> String {
    if listing.name(address).is_none()
        && listing.function_of(address).is_none()
        && let Some(object) = db.object(address)
        && let Some(name) = db.data_name(object.start)
    {
        return format!("{name}+{:X}", address - object.start);
    }
    listing.describe(address)
}

/// The cross-references to `address`, one per place made (the strongest
/// kind there), code's first, as chips say them.
pub fn xref_chips(db: &Database<'_>, listing: &Listing, address: u64) -> Vec<XrefChip> {
    let code = |kind: RefKind| matches!(kind, RefKind::Call | RefKind::Jump);
    let mut refs: Vec<&Reference> = db
        .references()
        .within(address..address.saturating_add(1))
        .iter()
        .collect();
    refs.sort_by_key(|r| (!code(r.kind), r.from, std::cmp::Reverse(r.kind)));
    refs.dedup_by_key(|r| r.from);
    refs.into_iter()
        .map(|r| {
            let arrow = if r.from < r.target { '↑' } else { '↓' };
            let letter = match r.kind {
                RefKind::Call => 'p',
                RefKind::Jump => 'j',
                RefKind::Read => 'r',
                RefKind::Write => 'w',
                RefKind::Address | RefKind::Pointer(_) => 'o',
            };
            XrefChip {
                from: r.from,
                source: source_of(db, listing, r.from),
                mark: format!("{arrow}{letter}"),
                code: code(r.kind),
            }
        })
        .collect()
}

/// `n` bytes, short (`612 B`, `4.2 KB`, `1.3 MB`).
#[expect(clippy::cast_precision_loss, reason = "a size to one decimal")]
pub fn size_text(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

impl Workspace {
    /// Whether pane `id` shows its listing as the unified listing.
    pub fn shows_unified(&self, id: PaneId) -> bool {
        matches!(self.layout.active(id), Some(TabKind::Listing))
            && self.panes.get(&id).is_some_and(|s| s.unified.on)
    }

    /// Pane `id`'s unified listing's layers, folds and expanded rows, to
    /// keep with its tab.
    pub fn unified_view_of(&self, id: PaneId) -> Option<UnifiedView> {
        let overlays = self.hex_overlays();
        Some(self.panes.get(&id)?.unified.view(&overlays))
    }

    /// The name and type columns of tree row `key`: its siblings' widest
    /// (its own, for a row with no parent).
    pub fn field_columns(&self, overlays: &[Overlay], key: &Key) -> (usize, usize) {
        let Some(parent) = key.parent() else {
            return (0, 0);
        };
        *self
            .unified
            .columns
            .borrow_mut()
            .entry(parent)
            .or_insert_with_key(|parent| hex_tree::child_columns(overlays, parent))
    }

    /// The address pane `id`'s cursor row starts at, if it is mapped.
    pub fn unified_address(&self, id: PaneId) -> Option<u64> {
        let u = &self.panes.get(&id)?.unified;
        // Where a jump is taking it, before its row is found (the sync
        // group follows at once).
        if let Some((address, _)) = u.target {
            return Some(address);
        }
        let b = self.unified.built.as_ref()?;
        let row = u.flat.as_ref()?.rows.get(u.cursor)?;
        b.doc.address(row, &b.listing, &b.image, &b.overlays)
    }

    /// What a rename, a comment or a type at pane `id`'s cursor row is
    /// for: a global's (any row of its tree), else the row's address.
    pub fn unified_subject(&self, id: PaneId) -> Option<u64> {
        let b = self.unified.built.as_ref()?;
        let u = &self.panes.get(&id)?.unified;
        let row = u.flat.as_ref()?.rows.get(u.cursor)?;
        if let RowKind::Field(line) = &row.kind
            && let Some(overlay) = b.overlays.get(line.key.root)
            && overlay.source == Source::Program
        {
            return b
                .image
                .position(overlay, Mode::Address, 0)
                .filter(|&a| b.image.holds(Mode::Address, a));
        }
        b.doc.address(row, &b.listing, &b.image, &b.overlays)
    }

    /// `Y` in pane `id`: Set type for the global the cursor's row is in,
    /// over the row; whether there is one.
    fn open_unified_type(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let field = self
            .unified_subject(id)
            .and_then(|a| self.session.as_ref()?.global_type(a))
            .and_then(|typed| TypeField::global(&typed));
        let Some(field) = field else {
            return false;
        };
        self.open_type_input(id, field, Place::Unified, window, cx);
        true
    }

    /// Where the Set type field over pane `id`'s cursor row shows, in the
    /// window (its text column), and the row's height; `None` with the
    /// row out of sight.
    pub fn unified_type_at(&mut self, id: PaneId) -> Option<(Point<Pixels>, f32)> {
        let sources = self.unified_sources()?;
        let cols = self.unified_columns(id, &sources);
        let row_h = self.row(self.settings.listing_line_height);
        let state = self.panes.get(&id)?;
        let u = &state.unified;
        let n = (u.cursor as u64).checked_sub(u.scroll.anchor.line)?;
        let y = f(n) * row_h - u.scroll.anchor.offset;
        let bounds = state.bounds.get();
        if y < 0.0 || y + row_h > f32::from(bounds.size.height) {
            return None;
        }
        // Over the row's type where it shows one, else at its text.
        let x = match self.unified.type_x.get() {
            Some((pane, row, x)) if pane == id && row == u.cursor => x,
            _ => cols.text,
        };
        Some((bounds.origin + point(px(x), px(y)), row_h))
    }

    /// An item's cross-references past its line's text, as one badge (row
    /// `k`'s): one reference is a chip naming where it is made, a press
    /// going there; more are their count, a press opening a menu of them
    /// to go to one.
    fn xref_badge(
        &self,
        chips: Vec<XrefChip>,
        (k, row_h): (usize, f32),
        quiet: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let color = if chips.iter().any(|c| c.code) {
            theme.code_xref
        } else {
            theme.data_xref
        };
        // Quiet (a plain block's, under its label): in the text's muted
        // colour, no fill until the pointer is on it.
        let (color, fill) = if quiet {
            (theme.text_placeholder, 0x00)
        } else {
            (color, 0x22)
        };
        let badge = div()
            .id(("unified-xrefs", k))
            .flex_none()
            .flex()
            .items_center()
            .gap(self.z(3.0))
            .ml(self.z(10.0))
            .h(px((row_h - 4.0).max(8.0)))
            .px(self.z(5.0))
            .rounded(self.z(4.0))
            .bg(hsla(with_alpha(color, fill)))
            .text_color(hsla(color))
            .hover(|s| s.bg(hsla(with_alpha(color, 0x44))))
            .cursor_pointer();
        let [chip] = chips.as_slice() else {
            let n = chips.len();
            return badge
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                        cx.stop_propagation();
                        let items = chips
                            .iter()
                            .map(|c| {
                                let from = c.from;
                                let mut item = OwnItem::new(
                                    format!("{} {}", c.mark, c.source),
                                    move |this, _, cx| this.jump(from, cx),
                                );
                                item.key = Some(format!("{from:X}"));
                                item
                            })
                            .collect();
                        // Its row's item, by where its references are from.
                        let opener = format!("xrefs {k} {:x}", chips.first().map_or(0, |c| c.from));
                        this.toggle_own_menu(opener, e.position, items, window, cx);
                    }),
                )
                .child(format!("{n} xrefs"))
                .child(icon(IconName::ChevronDown, self.z(ICON - 3.0), hsla(color)))
                .into_any_element();
        };
        let from = chip.from;
        badge
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    cx.stop_propagation();
                    this.jump(from, cx);
                    cx.notify();
                }),
            )
            .child(format!("{} {}", chip.mark, chip.source))
            .into_any_element()
    }

    /// Shows pane `id`'s listing as the unified listing at the shared
    /// cursor.
    pub fn show_unified(&mut self, id: PaneId) {
        let address = self.current_address();
        if let Some(state) = self.panes.get_mut(&id) {
            state.unified.on = true;
            state.unified.target = address.map(|a| (a, true));
        }
    }

    /// Pane `id` back to what its listing tab showed before.
    pub fn leave_unified(&mut self, id: PaneId) {
        if let Some(state) = self.panes.get_mut(&id) {
            state.unified.on = false;
        }
    }

    /// Pane `id` shows its listing tab as the unified listing (the hex
    /// view, the call graph and the graph left).
    pub fn enter_unified(&mut self, id: PaneId) {
        self.set_code_view(id, &TabKind::Listing);
        self.leave_hex(id);
        self.leave_calls(id);
        self.set_graph(id, false);
        self.show_unified(id);
    }

    /// The document, made again when the listing, the byte space or the
    /// overlays changed (every pane's rows flattened again, its cursor
    /// found again by its address).
    fn unified_sources(&mut self) -> Option<Sources> {
        self.ensure_hex();
        // Every typed global, laid out once (the first time: all of
        // them).
        let started = Instant::now();
        if self.lay_out_all_globals() {
            trace!(
                "unified globals laid out: {:.1} ms",
                started.elapsed().as_secs_f64() * 1e3
            );
        }
        let listing = self.listing.clone()?;
        let image = self.hex_image()?;
        let overlays = self.hex_overlays();
        let fresh = self.unified.built.as_ref().is_some_and(|b| {
            Arc::ptr_eq(&b.listing, &listing)
                && Arc::ptr_eq(&b.image, &image)
                && Arc::ptr_eq(&b.overlays, &overlays)
        });
        if !fresh {
            let started = Instant::now();
            let session = self.session.as_ref()?;
            let analysis = session.revision().analysis;
            let loops = match &self.unified.loops {
                Some((of, loops)) if *of == analysis => Arc::clone(loops),
                Some(_) | None => {
                    let loops = Arc::new(loop_regions(session.database()?.program()));
                    self.unified.loops = Some((analysis, Arc::clone(&loops)));
                    loops
                }
            };
            let doc = Arc::new(Document::build(&image, &listing, &overlays, loops));
            // The trees' rows are others now.
            self.unified.columns.borrow_mut().clear();
            trace!(
                "unified document: {} items, {} loops, {:.1} ms",
                doc.items.len(),
                doc.loops.len(),
                started.elapsed().as_secs_f64() * 1e3
            );
            let ids: Vec<PaneId> = self.panes.keys().copied().collect();
            for id in ids {
                let address = self.cursor_address(id);
                if let Some(state) = self.panes.get_mut(&id) {
                    let u = &state.unified;
                    if u.on
                        && let Some(screen) = (u.cursor as u64).checked_sub(u.scroll.anchor.line)
                    {
                        self.unified.kept.insert(id, screen);
                    }
                    state.unified.flat = None;
                    if state.unified.target.is_none() {
                        state.unified.target = address.map(|a| (a, false));
                    }
                }
            }
            self.unified.built = Some(Built {
                listing,
                image,
                overlays,
                doc,
            });
        }
        let b = self.unified.built.as_ref()?;
        Some((
            Arc::clone(&b.doc),
            Arc::clone(&b.listing),
            Arc::clone(&b.image),
            Arc::clone(&b.overlays),
        ))
    }

    /// Pane `id`'s rows, flattened again if they were dropped.
    fn unified_flat(&mut self, id: PaneId, sources: &Sources) -> Option<Arc<Flat>> {
        let (doc, listing, _, overlays) = sources;
        // A tab's expanded rows, once their overlays are laid out.
        if let Some(state) = self.panes.get_mut(&id) {
            state.unified.expand_pending(overlays);
        }
        let state = self.panes.get(&id)?;
        if let Some(flat) = &state.unified.flat {
            return Some(Arc::clone(flat));
        }
        let session = self.session.as_ref()?;
        let (file, _) = session.loaded()?;
        let inputs = Inputs {
            overlays,
            listing,
            file,
        };
        let started = Instant::now();
        let flat = Arc::new(doc.flatten(&state.unified, &inputs));
        trace!(
            "unified rows: {}, {:.1} ms",
            flat.len(),
            started.elapsed().as_secs_f64() * 1e3
        );
        let state = self.panes.get_mut(&id)?;
        state.unified.flat = Some(Arc::clone(&flat));
        state.unified.cursor = state.unified.cursor.min(flat.len().saturating_sub(1));
        // Its rows are others now.
        state.unified.selection.clear();
        Some(flat)
    }

    /// Pane `id`'s cursor row and its place on screen (rows from the top),
    /// to keep across a reflow.
    fn unified_kept(&self, id: PaneId) -> Option<(Row, i64)> {
        let u = &self.panes.get(&id)?.unified;
        let row = u.flat.as_ref()?.rows.get(u.cursor)?.clone();
        let screen = i64::try_from(u.cursor).ok()? - i64::try_from(u.scroll.anchor.line).ok()?;
        Some((row, screen))
    }

    /// Pane `id`'s rows flattened again (a fold or a layer changed), the
    /// cursor on `kept` (the row it was on; else its address) where it was
    /// on screen.
    fn unified_reflow(&mut self, id: PaneId, kept: Option<(Row, i64)>, sources: &Sources) {
        let (doc, listing, image, overlays) = sources;
        if let Some(state) = self.panes.get_mut(&id) {
            state.unified.flat = None;
        }
        let Some(flat) = self.unified_flat(id, sources) else {
            return;
        };
        let Some((row, screen)) = kept else {
            return;
        };
        let cursor = flat.find(&row).or_else(|| {
            let address = doc.address(&row, listing, image, overlays)?;
            doc.row_of(&flat, address, listing, image, overlays)
        });
        let visible = self.rows(id, self.settings.listing_line_height);
        if let (Some(cursor), Some(state)) = (cursor, self.panes.get_mut(&id)) {
            let screen = u64::try_from(screen.max(0)).unwrap_or(0);
            state
                .unified
                .land(&flat, cursor, Landing::Kept(screen), visible);
        }
    }

    /// Pane `id`'s cursor moved to row `row` (revealed; as a jump if
    /// `focus`): its listing cursor at the row's address, the sync group
    /// following.
    fn unified_to(&mut self, id: PaneId, row: usize, focus: bool, sources: &Sources) {
        let (doc, listing, image, overlays) = sources;
        let visible = self.rows(id, self.settings.listing_line_height);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let Some(flat) = state.unified.flat.clone() else {
            return;
        };
        let how = if focus { Landing::Jump } else { Landing::Step };
        state.unified.land(&flat, row, how, visible);
        let line = flat
            .rows
            .get(state.unified.cursor)
            .and_then(|r| doc.listing_line(r, listing, image, overlays));
        if let Some(line) = line {
            state.listing.cursor = line;
            state.listing.lit = None;
            state.listing.selection.clear();
            state.listing.token = None;
            self.moved(id);
        }
    }

    /// Pane `id`'s cursor to the address the sync group or a jump moved
    /// it to, if any.
    fn unified_follow(&mut self, id: PaneId, sources: &Sources, flat: &Flat) {
        let (doc, listing, image, overlays) = sources;
        let Some((address, focus)) = self
            .panes
            .get_mut(&id)
            .and_then(|s| s.unified.target.take())
        else {
            return;
        };
        let Some(row) = doc.row_of(flat, address, listing, image, overlays) else {
            return;
        };
        let visible = self.rows(id, self.settings.listing_line_height);
        let kept = self.unified.kept.remove(&id);
        if let Some(state) = self.panes.get_mut(&id) {
            let u = &mut state.unified;
            // Where it was on screen, the document made again; a jump's
            // row lit a moment.
            let how = match kept {
                Some(screen) => Landing::Kept(screen),
                None if focus => Landing::Jump,
                None => Landing::Follow,
            };
            u.land(flat, row, how, visible);
            if how == Landing::Jump {
                u.landed = Some((row, Instant::now()));
            }
        }
    }

    /// Folds or opens the card (or tree row) at pane `id`'s row `row`;
    /// `open`: only if it would open (`Some(true)`) or close
    /// (`Some(false)`). Whether it did.
    fn unified_toggle(
        &mut self,
        id: PaneId,
        row: usize,
        open: Option<bool>,
        sources: &Sources,
    ) -> bool {
        let (doc, listing, ..) = sources;
        let Some(state) = self.panes.get_mut(&id) else {
            return false;
        };
        let Some(r) = state
            .unified
            .flat
            .as_ref()
            .and_then(|f| f.rows.get(row))
            .cloned()
        else {
            return false;
        };
        let screen = i64::try_from(row).unwrap_or(0)
            - i64::try_from(state.unified.scroll.anchor.line).unwrap_or(0);
        match &r.kind {
            RowKind::Card {
                item,
                piece,
                open: now,
            } => {
                if open.is_some_and(|o| o == *now) {
                    return false;
                }
                if piece.is_some_and(|p| {
                    doc.items
                        .get(*item)
                        .and_then(|i| i.pieces.get(p))
                        .is_some_and(|p| matches!(p, Piece::Lines(_) | Piece::Uninitialised(_)))
                }) {
                    return false;
                }
                state.unified.cursor = row;
                doc.toggle(&mut state.unified, *item, *piece);
            }
            RowKind::Field(line) => {
                if !line.expandable || open.is_some_and(|o| o == line.expanded) {
                    return false;
                }
                state.unified.cursor = row;
                state.unified.tree.toggle(&line.key);
                state.unified.flat = None;
            }
            RowKind::Block { line, open: now } => {
                let Some(address) = listing.line(*line).map(|l| l.address) else {
                    return false;
                };
                if open.is_some_and(|o| o == *now) {
                    return false;
                }
                state.unified.cursor = row;
                state.unified.flip(Fold::Block(address));
            }
            RowKind::Line(_)
            | RowKind::Hex(_)
            | RowKind::Run { .. }
            | RowKind::Bytes(_)
            | RowKind::Uninitialised(_)
            | RowKind::Spacer => return false,
        }
        self.unified_reflow(id, Some((r, screen)), sources);
        true
    }

    /// The row the parent card or tree row of pane `id`'s row `row` is
    /// at: the nearest above it less deep.
    fn unified_parent(&self, id: PaneId, row: usize) -> Option<usize> {
        let flat = self.panes.get(&id)?.unified.flat.as_ref()?;
        let depth = flat.rows.get(row)?.depth;
        (0..row).rev().find(|&k| {
            flat.rows.get(k).is_some_and(|r| {
                r.depth < depth
                    && matches!(
                        r.kind,
                        RowKind::Card { .. } | RowKind::Field(_) | RowKind::Block { .. }
                    )
            })
        })
    }

    /// Runs `command` where the unified listing takes it; whether it did.
    /// A view's command leaves it first.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "the unified listing takes a few of the registry's commands; `run` the rest"
    )]
    pub fn unified_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let id = self.layout.focused();
        if command == Command::ToggleUnified {
            if self.shows_unified(id) {
                self.leave_unified(id);
            } else {
                self.enter_unified(id);
            }
            return true;
        }
        if !self.shows_unified(id) {
            return false;
        }
        match command {
            Command::ToggleGraph
            | Command::ToggleHex
            | Command::ShowInHex
            | Command::ToggleCalls
            | Command::SwitchView => {
                self.leave_unified(id);
                return false;
            }
            _ => {}
        }
        let Some(sources) = self.unified_sources() else {
            return false;
        };
        let Some(flat) = self.unified_flat(id, &sources) else {
            return false;
        };
        let Some(cursor) = self.panes.get(&id).map(|s| s.unified.cursor) else {
            return false;
        };
        let visible = usize::try_from(self.rows(id, self.settings.listing_line_height))
            .unwrap_or(1)
            .saturating_sub(2)
            .max(1);
        let last = flat.len().saturating_sub(1);
        let to = match command {
            Command::MoveUp => cursor.saturating_sub(1),
            Command::MoveDown => (cursor + 1).min(last),
            Command::PageUp => cursor.saturating_sub(visible),
            Command::PageDown => (cursor + visible).min(last),
            Command::Top => 0,
            Command::Bottom => last,
            Command::Follow => return self.unified_toggle(id, cursor, None, &sources),
            Command::SetType => return self.open_unified_type(id, window, cx),
            Command::ApplyType => {
                self.open_type_field(id, window, cx);
                return true;
            }
            Command::RemoveType => {
                self.remove_user_type(id);
                return true;
            }
            Command::CopyHex => {
                self.copy_hex(id, CopyFormat::Hex, cx);
                return true;
            }
            Command::CopyEscaped => {
                self.copy_hex(id, CopyFormat::Bytes, cx);
                return true;
            }
            Command::CopyCArray => {
                self.copy_hex(id, CopyFormat::CArray, cx);
                return true;
            }
            _ => return false,
        };
        let to = past_spacers(&flat, to, to < cursor);
        if let Some(state) = self.panes.get_mut(&id) {
            state.unified.selection.leave(cursor as u64, false);
        }
        self.unified_to(id, to, false, &sources);
        true
    }

    /// Left and Right in pane `id`: fold the cursor's card (else go to
    /// its parent's), open it (else go to its first child). With Shift, Up,
    /// Down, Page Up and Page Down select rows.
    fn unified_key(&mut self, id: PaneId, e: &KeyDownEvent) -> bool {
        let k = &e.keystroke;
        let m = k.modifiers;
        let commenting = self.comment.as_ref().is_some_and(|c| c.pane == id);
        if m.alt || m.control || m.platform || commenting || !self.shows_unified(id) {
            return false;
        }
        if m.shift {
            return self.unified_extend(id, k.key.as_str());
        }
        let right = match k.key.as_str() {
            "right" => true,
            "left" => false,
            _ => return false,
        };
        let Some(sources) = self.unified_sources() else {
            return false;
        };
        let Some(cursor) = self.panes.get(&id).map(|s| s.unified.cursor) else {
            return false;
        };
        if self.unified_toggle(id, cursor, Some(right), &sources) {
            return true;
        }
        let to = if right {
            Some(cursor + 1)
        } else {
            self.unified_parent(id, cursor)
        };
        if let Some(to) = to {
            self.unified_to(id, to, false, &sources);
        }
        true
    }

    /// Shift with `key` in pane `id`: the selection grown from the cursor
    /// by a row (Up, Down) or a page; whether it was one of those.
    fn unified_extend(&mut self, id: PaneId, key: &str) -> bool {
        let page = usize::try_from(self.rows(id, self.settings.listing_line_height))
            .unwrap_or(1)
            .saturating_sub(2)
            .max(1);
        let Some(sources) = self.unified_sources() else {
            return false;
        };
        let Some(flat) = self.unified_flat(id, &sources) else {
            return false;
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return false;
        };
        let cursor = state.unified.cursor;
        let last = flat.len().saturating_sub(1);
        let to = match key {
            "up" => cursor.saturating_sub(1),
            "down" => (cursor + 1).min(last),
            "pageup" => cursor.saturating_sub(page),
            "pagedown" => (cursor + page).min(last),
            _ => return false,
        };
        let to = past_spacers(&flat, to, to < cursor);
        state.unified.selection.leave(cursor as u64, true);
        self.unified_to(id, to, false, &sources);
        true
    }

    /// Pane `id`'s rows selected, else its cursor's row.
    fn unified_selected(&self, id: PaneId) -> Option<RangeInclusive<u64>> {
        let u = &self.panes.get(&id)?.unified;
        let cursor = u.cursor as u64;
        Some(u.selection.range(cursor).unwrap_or(cursor..=cursor))
    }

    /// Copy in pane `id`: its rows selected (else the cursor's) as they
    /// show, at most [`MOST_COPIED`] of them ([`row_text`]).
    pub fn unified_selection_text(&self, id: PaneId) -> Option<String> {
        let built = self.unified.built.as_ref()?;
        let sources = (
            Arc::clone(&built.doc),
            Arc::clone(&built.listing),
            Arc::clone(&built.image),
            Arc::clone(&built.overlays),
        );
        let flat = self.panes.get(&id)?.unified.flat.as_ref()?;
        let ctx = self.rows_ctx(id, &sources)?;
        let text: Vec<String> = self
            .unified_selected(id)?
            .take(usize::try_from(MOST_COPIED).unwrap_or(usize::MAX))
            .filter_map(|k| flat.rows.get(usize::try_from(k).ok()?))
            .filter_map(|row| self.row_view(&ctx, row))
            .map(|v| row_text(&v, &ctx.cols))
            .collect();
        Some(text.join("\n"))
    }

    /// Where row `k` of pane `id` is in `mode`'s space (a spacer: where the
    /// row after it is).
    fn unified_row_place(&self, id: PaneId, k: u64, mode: Mode) -> Option<u64> {
        let b = self.unified.built.as_ref()?;
        let flat = self.panes.get(&id)?.unified.flat.as_ref()?;
        let k = past_spacers(flat, usize::try_from(k).ok()?, false);
        let row = flat.rows.get(k)?;
        match mode {
            Mode::Address => b.doc.address(row, &b.listing, &b.image, &b.overlays),
            Mode::File => b.doc.offset(row, &b.image, &b.overlays),
        }
    }

    /// Where pane `id`'s cursor row is: its address, else its file offset.
    pub fn unified_place(&self, id: PaneId) -> Option<(Mode, u64)> {
        let cursor = self.panes.get(&id)?.unified.cursor as u64;
        [Mode::Address, Mode::File]
            .into_iter()
            .find_map(|mode| Some((mode, self.unified_row_place(id, cursor, mode)?)))
    }

    /// The bytes pane `id`'s rows selected (else its cursor's row) hold,
    /// in the space of the first's place ([`Self::unified_place`]): its
    /// first byte to the next row's.
    pub fn unified_byte_range(&self, id: PaneId) -> Option<(Mode, std::ops::Range<u64>)> {
        let u = &self.panes.get(&id)?.unified;
        let cursor = u.cursor as u64;
        let rows = u.selection.range(cursor).unwrap_or(cursor..=cursor);
        let (mode, start) = [Mode::Address, Mode::File]
            .into_iter()
            .find_map(|mode| Some((mode, self.unified_row_place(id, *rows.start(), mode)?)))?;
        let end = self
            .unified_row_place(id, rows.end() + 1, mode)
            .filter(|&e| e > start)
            .or_else(|| {
                self.unified_row_place(id, *rows.end(), mode)
                    .map(|a| a.max(start) + 1)
            })?;
        Some((mode, start..end))
    }

    /// The bytes pane `id`'s rows selected hold, by address (see
    /// [`Self::unified_byte_range`]), and whether the cursor is on the
    /// first; `None` without a selection or for rows of no address.
    pub fn unified_bytes(&self, id: PaneId) -> Option<(u64, u64, bool)> {
        let u = &self.panes.get(&id)?.unified;
        let rows = u.selection.range(u.cursor as u64)?;
        let (Mode::Address, bytes) = self.unified_byte_range(id)? else {
            return None;
        };
        let first = u.cursor as u64 == *rows.start() && rows.start() != rows.end();
        Some((bytes.start, bytes.end, first))
    }

    /// Select All in pane `id`: the rows of the card holding the cursor
    /// (its own, on a card), the cursor on the card.
    pub fn unified_select_all(&mut self, id: PaneId) {
        let Some(sources) = self.unified_sources() else {
            return;
        };
        let Some(flat) = self.unified_flat(id, &sources) else {
            return;
        };
        let Some(cursor) = self.panes.get(&id).map(|s| s.unified.cursor) else {
            return;
        };
        let depth = flat.rows.get(cursor).map_or(0, |r| r.depth);
        let card = |k: usize| {
            flat.rows
                .get(k)
                .filter(|r| matches!(r.kind, RowKind::Card { .. }))
        };
        let Some(header) = (0..=cursor)
            .rev()
            .find(|&k| card(k).is_some_and(|r| k == cursor || r.depth < depth))
        else {
            return;
        };
        let top = card(header).map_or(0, |r| r.depth);
        let end = (header + 1..flat.len())
            .find(|&k| flat.rows.get(k).is_some_and(|r| r.depth <= top))
            .unwrap_or(flat.len())
            .saturating_sub(1);
        self.unified_to(id, header, false, &sources);
        if let Some(state) = self.panes.get_mut(&id) {
            state.unified.selection.anchor = Some(end as u64);
            state.unified.selection.pressed = None;
        }
    }

    /// A press in pane `id`: on the scrollbar, its thumb or a page; on a
    /// row, the cursor there, its card folded or opened by the chevron or
    /// a double-click.
    /// On a line's token, the token the cursor's (its equals lit), a
    /// double-click going where it names; Ctrl+click or a middle click on
    /// a name opens it in a new tab.
    fn unified_down(
        &mut self,
        id: PaneId,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(state) = self.panes.get(&id) else {
            return;
        };
        window.focus(&state.focus, cx);
        self.layout.focus(id);
        // A click elsewhere in the pane drops the comment field (a click
        // in it moves its caret).
        if self.comment.as_ref().is_some_and(|c| c.pane == id) {
            self.comment = None;
        }
        let b = state.bounds.get();
        let x = f32::from(e.position.x - b.origin.x);
        let y = f32::from(e.position.y - b.origin.y);
        if x > f32::from(b.size.width) - f32::from(self.z(SCROLLBAR)) {
            self.scrollbar_down(id, e.position.y);
            cx.notify();
            return;
        }
        let Some(sources) = self.unified_sources() else {
            return;
        };
        let Some(flat) = self.unified_flat(id, &sources) else {
            return;
        };
        let Some(state) = self.panes.get(&id) else {
            return;
        };
        let row_h = self.row(self.settings.listing_line_height);
        let anchor = state.unified.scroll.anchor;
        // An arrow's stub: where its other end is.
        let under = anchor.line + rows_in(y + anchor.offset + 1.0, row_h) - 1;
        if let Some(target) = self.stub_end(id, x, y, Some(under)) {
            self.jump(target, cx);
            cx.notify();
            return;
        }
        // A pinned header: the view goes to it (folded, by its chevron).
        let pinned = flat.pinned(usize::try_from(anchor.line).unwrap_or(0));
        let slot = usize::try_from(rows_in(y + 1.0, row_h).saturating_sub(1)).unwrap_or(0);
        if let Some(&header) = pinned.get(slot) {
            let cols = self.unified_columns(id, &sources);
            if (cols.fold..cols.fold + 2.0 * cols.cw).contains(&x) {
                self.unified_toggle(id, header, Some(false), &sources);
            }
            self.unified_to(id, header, true, &sources);
            cx.notify();
            return;
        }
        let row = anchor.line + rows_in(y + anchor.offset + 1.0, row_h) - 1;
        let Some(row) = usize::try_from(row).ok().filter(|&r| r < flat.len()) else {
            return;
        };
        let row = past_spacers(&flat, row, false);
        // The chevron: a card's and a block's in the fold column, a tree
        // row's left of its name.
        let cols = self.unified_columns(id, &sources);
        let chevron = match flat.rows.get(row) {
            Some(Row {
                kind: RowKind::Field(_),
                depth,
            }) => cols.text + f(u64::from(depth.saturating_sub(1)) * 2) * cols.cw - 2.0 * cols.cw,
            Some(_) | None => cols.fold,
        };
        let on_chevron = (chevron..chevron + 2.0 * cols.cw).contains(&x);
        let token = self.unified_token(id, row, x, &sources);
        let named = token.as_ref().and_then(|(_, t)| t.target);
        if self.open_name(id, named, name_click(e, cx), window, cx) {
            return;
        }
        // A left press may start a drag selecting rows (with Shift it
        // extends from the cursor); any other drops the selection.
        if let Some(state) = self.panes.get_mut(&id) {
            let pane = &mut state.unified;
            if e.button == MouseButton::Left {
                pane.selection
                    .press(row as u64, pane.cursor as u64, e.modifiers.shift);
            } else {
                pane.selection.clear();
            }
        }
        self.unified_to(id, row, false, &sources);
        if let Some((i, t)) = token
            && let Some(state) = self.panes.get_mut(&id)
        {
            state.listing.token = Some(i);
            if highlightable(t.role) {
                let again = state.listing.highlight.as_deref() == Some(t.text.as_str());
                state.listing.highlight = (!again || e.click_count > 1).then(|| t.text.clone());
            }
            if e.click_count == 2
                && t.role != Role::Prefix
                && let Some(target) = t.target
            {
                self.jump(target, cx);
                cx.notify();
                return;
            }
        }
        if e.button == MouseButton::Left && (on_chevron || e.click_count == 2) {
            self.unified_toggle(id, row, None, &sources);
        }
        cx.notify();
    }

    /// A drag from a press in pane `id` onto a row: the cursor follows it,
    /// the rows from the one pressed selected; whether it was such a drag.
    fn unified_drag(&mut self, id: PaneId, e: &MouseMoveEvent) -> bool {
        let row_h = self.row(self.settings.listing_line_height);
        let Some(state) = self.panes.get_mut(&id) else {
            return false;
        };
        if state.unified.selection.pressed.is_none() {
            return false;
        }
        let b = state.bounds.get();
        let y = f32::from(e.position.y - b.origin.y).max(0.0);
        let anchor = state.unified.scroll.anchor;
        let len = state.unified.flat.as_ref().map_or(0, |f| f.len());
        let row = (anchor.line + rows_in(y + anchor.offset + 1.0, row_h))
            .saturating_sub(1)
            .min(len.saturating_sub(1) as u64);
        if !state.unified.selection.drag(row) {
            return false;
        }
        let Some(sources) = self.unified_sources() else {
            return false;
        };
        self.unified_to(id, usize::try_from(row).unwrap_or(0), false, &sources);
        true
    }

    /// The token of row `row` of pane `id` at `x` (the pane's pixels), on
    /// a line's text: its index in the line's rendering, and it.
    fn unified_token(
        &self,
        id: PaneId,
        row: usize,
        x: f32,
        sources: &Sources,
    ) -> Option<(usize, Token)> {
        let (_, listing, ..) = sources;
        let flat = self.panes.get(&id)?.unified.flat.as_ref()?;
        let RowKind::Line(n) = flat.rows.get(row)?.kind else {
            return None;
        };
        let session = self.session.as_ref()?;
        let cols = self.unified_columns(id, sources);
        if x < cols.text {
            return None;
        }
        let mut tokens = listing
            .render(session.database()?, n, session.overlay())
            .tokens;
        // The text column starts past the listing's prefix and padding.
        let skipped: usize = tokens
            .iter()
            .take_while(|t| matches!(t.role, Role::Prefix | Role::Space | Role::OpcodeBytes))
            .map(|t| t.text.chars().count())
            .sum();
        let col =
            usize::try_from(rows_in(x - cols.text + 1.0, cols.cw).saturating_sub(1)).unwrap_or(0);
        let i = token_at(&tokens, skipped + col)?;
        let token = tokens.swap_remove(i);
        (!matches!(token.role, Role::Space | Role::CodeXref | Role::DataXref)).then_some((i, token))
    }

    /// The pointer moved in pane `id`: dragging the scrollbar's thumb, or
    /// over a row, an instruction's linked to the C (its statement lit
    /// there), a name peeked at.
    fn unified_move(
        &mut self,
        id: PaneId,
        e: &MouseMoveEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.scrollbar_move(id, e) {
            cx.notify();
            return;
        }
        if e.dragging() && self.unified_drag(id, e) {
            cx.notify();
            return;
        }
        let Some(state) = self.panes.get(&id) else {
            return;
        };
        let b = state.bounds.get();
        let y = f32::from(e.position.y - b.origin.y);
        let across = f32::from(e.position.x - b.origin.x);
        let anchor = state.unified.scroll.anchor;
        let row_h = self.row(self.settings.listing_line_height);
        let row = anchor.line + rows_in(y + anchor.offset + 1.0, row_h) - 1;
        // Under the pinned headers, no line.
        let flat = state.unified.flat.as_ref();
        let under = flat.map_or(0, |f| {
            f.pinned(usize::try_from(anchor.line).unwrap_or(0)).len()
        });
        let slot = usize::try_from(rows_in(y + 1.0, row_h).saturating_sub(1)).unwrap_or(0);
        let at_row = usize::try_from(row).ok().filter(|_| slot >= under);
        let line = at_row
            .and_then(|k| flat?.rows.get(k))
            .and_then(|r| match r.kind {
                RowKind::Line(n) => self.listing.as_ref()?.line(n),
                RowKind::Card { .. }
                | RowKind::Block { .. }
                | RowKind::Field(_)
                | RowKind::Hex(_)
                | RowKind::Run { .. }
                | RowKind::Bytes(_)
                | RowKind::Uninitialised(_)
                | RowKind::Spacer => None,
            });
        let hovered = line
            .filter(|l| l.kind == LineKind::Instruction)
            .map(|l| Link::Listing(l.address));
        if self.link != hovered {
            self.link = hovered;
            cx.notify();
        }
        let stub = self.stub_end(id, across, y, at_row.map(|k| k as u64));
        let peeked = stub.or_else(|| {
            let b = self.unified.built.as_ref()?;
            let sources = (
                Arc::clone(&b.doc),
                Arc::clone(&b.listing),
                Arc::clone(&b.image),
                Arc::clone(&b.overlays),
            );
            let (_, t) = self.unified_token(id, at_row?, across, &sources)?;
            t.target.filter(|_| peekable(t.role))
        });
        self.hover_peek(peeked, None, e.position, window, cx);
    }

    /// The other end of the arrow stub under `(x, y)` (pane `id`'s
    /// pixels), the pointer on row `row`: the stub at a jump names its
    /// target, the one at a target its jump.
    fn stub_end(&self, id: PaneId, x: f32, y: f32, row: Option<u64>) -> Option<u64> {
        let stubs = self.unified.stubs.borrow();
        let drawn = stubs.get(&id)?;
        let (from, to) = arrows::hit_at(&drawn.hits, x - drawn.left, y)?;
        let &(source, target) = drawn.ends.get(&(from, to))?;
        Some(if row == Some(from) { target } else { source })
    }

    /// Where pane `id`'s rows' parts go: the fold chevrons by the left
    /// edge, the address (the widest position), the bytes (an
    /// instruction's first [`BYTES_SHOWN`], if shown), the marks (the
    /// arrows' width), the text.
    pub fn unified_columns(&self, id: PaneId, sources: &Sources) -> Columns {
        let (_, listing, image, _) = sources;
        let cw = self.char_width.unwrap_or(8.0);
        let digits = image
            .prefix_width(Mode::Address)
            .max(image.prefix_width(Mode::File));
        let shows_bytes = self.panes.get(&id).is_some_and(|s| s.unified.layers.bytes)
            && listing.options().opcode_bytes == 0;
        let fold = f32::from(self.z(5.0));
        let address = fold + 2.0 * cw;
        let bytes = address + f(digits as u64 + 1) * cw;
        let marks = bytes
            + if shows_bytes {
                f(BYTES_SHOWN as u64 * 3 + 1) * cw
            } else {
                cw
            };
        Columns {
            fold,
            address,
            bytes,
            marks,
            text: marks + self.gutter_width(),
            shows_bytes,
            cw,
        }
    }

    /// Reads the decompiler's signatures out of the C the panes show:
    /// each document's declarations of the functions it calls (`int
    /// f(int); /* 0x1450 */`), by the address noted, and its own
    /// signature.
    fn harvest_signatures(&mut self) {
        let docs: Vec<Arc<CDocument>> = self
            .layout
            .panes()
            .filter_map(|p| self.document(&p.tabs.get(p.active)?.content))
            .cloned()
            .collect();
        for doc in docs {
            let ui = &mut self.unified;
            if ui.harvested.iter().any(|d| Arc::ptr_eq(d, &doc)) {
                continue;
            }
            let body = doc.body_start();
            ui.signatures.insert(doc.entry, (Arc::clone(&doc), body));
            for (n, line) in doc.lines.iter().enumerate().take(body) {
                let named = line.spans.clone().any(|s| {
                    doc.spans
                        .get(s)
                        .is_some_and(|span| span.kind == CTokenKind::Function)
                });
                // The note on the declaration's last line (its parameters
                // may wrap).
                let last = signature_lines(&doc, n).end.saturating_sub(1).max(n);
                let noted = doc
                    .lines
                    .get(last)
                    .into_iter()
                    .flat_map(|line| line.spans.clone().rev())
                    .find(|&s| {
                        doc.spans
                            .get(s)
                            .is_some_and(|span| span.kind == CTokenKind::Comment)
                    })
                    .and_then(|s| {
                        let hex = doc.span_text(s).strip_prefix("/* 0x")?;
                        let digits = hex.split(|c: char| !c.is_ascii_hexdigit()).next()?;
                        u64::from_str_radix(digits, 16).ok()
                    });
                if let (true, Some(entry)) = (named, noted) {
                    ui.signatures
                        .entry(entry)
                        .or_insert_with(|| (Arc::clone(&doc), n));
                }
            }
            ui.harvested.push(doc);
            if ui.harvested.len() > HARVESTED {
                ui.harvested.remove(0);
            }
        }
    }

    /// The decompiler's signature of the function at `entry` as text
    /// parts (its name bold), from its own printed C, else a printed
    /// caller's declaration of it; none if no C says it.
    pub fn unified_signature(&self, entry: u64, own: Option<&Arc<CDocument>>) -> Option<Vec<Part>> {
        let (doc, line) = if let Some(doc) = own {
            (doc, doc.body_start())
        } else {
            let (doc, line) = self.unified.signatures.get(&entry)?;
            (doc, *line)
        };
        let theme = self.theme;
        let mut parts = Vec::new();
        // Its parameters may wrap: the lines up to its closing `)`, as one.
        'lines: for (i, n) in signature_lines(doc, line).enumerate() {
            let shown = doc.shown_line(n, None);
            // A further line's first word follows a space (its indent
            // goes).
            let mut fresh = i > 0;
            for piece in &shown.pieces {
                let span = piece.span.and_then(|s| doc.spans.get(s));
                // A declaration ends at its `;` (its note after).
                if span.is_some_and(|s| s.kind == CTokenKind::Comment)
                    || shown.text.get(piece.range.clone()) == Some(";")
                {
                    break 'lines;
                }
                let text = shown.text.get(piece.range.clone())?;
                let text = if fresh || parts.is_empty() {
                    text.trim_start()
                } else {
                    text
                };
                if text.is_empty() {
                    continue;
                }
                let after = if fresh && !parts.is_empty() { " " } else { "" };
                fresh = false;
                let bold = span.is_some_and(|s| s.kind == CTokenKind::Function);
                parts.push((
                    format!("{after}{text}"),
                    span.map_or(theme.variable, |s| theme.c(s)),
                    bold,
                ));
            }
        }
        (!parts.is_empty()).then_some(parts)
    }

    /// The C statement of control the block at `address` starts with, in
    /// `doc` (its function's printed C), as faint text parts: the first
    /// line made from the instruction there that is an `if`, a loop, a
    /// `switch`, a `return`...
    pub fn block_snippet(&self, doc: &CDocument, address: u64) -> Vec<Part> {
        let theme = self.theme;
        let Some(line) = doc
            .lines_of(address)
            .find(|&n| is_control(doc.line_text(n)))
        else {
            return Vec::new();
        };
        let shown = doc.shown_line(line, None);
        let mut parts: Vec<Part> = Vec::new();
        for piece in &shown.pieces {
            let Some(text) = shown.text.get(piece.range.clone()) else {
                continue;
            };
            let text = if parts.is_empty() {
                text.trim_start()
            } else {
                text
            };
            if text.is_empty() {
                continue;
            }
            let color = piece
                .span
                .and_then(|s| doc.spans.get(s))
                .map_or(theme.variable, |s| theme.c(s));
            parts.push((text.to_owned(), with_alpha(color, 0xb0), false));
        }
        // A block's opening brace says nothing here.
        if parts.last().is_some_and(|p| p.0.trim() == "{") {
            parts.pop();
        }
        parts
    }

    /// The unified listing's tools in pane `id`'s toolbar: its layers.
    pub fn unified_tools(&self, id: PaneId, cx: &mut Context<Self>) -> Option<AnyElement> {
        if !self.shows_unified(id) {
            return None;
        }
        let layers = self.panes.get(&id)?.unified.layers;
        let toggle = |name: IconName,
                      label: &'static str,
                      on: bool,
                      flip: fn(&mut Layers),
                      cx: &mut Context<Self>|
         -> Stateful<gpui_kit::Div> {
            let theme = self.theme;
            div()
                .id(label)
                .flex()
                .flex_none()
                .items_center()
                .justify_center()
                .size(self.z(ICON_BUTTON))
                .rounded(self.z(4.0))
                .when(on, |d| d.bg(hsla(theme.element_selected)))
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .tooltip(self.keyed_tooltip(label, None))
                .on_mouse_down(MouseButton::Left, |_, window, cx| {
                    window.prevent_default();
                    cx.stop_propagation();
                })
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.layout.focus(id);
                    let Some(sources) = this.unified_sources() else {
                        return;
                    };
                    let kept = this.unified_kept(id);
                    if let Some(state) = this.panes.get_mut(&id) {
                        flip(&mut state.unified.layers);
                    }
                    this.unified_reflow(id, kept, &sources);
                    cx.notify();
                }))
                .child(icon(
                    name,
                    self.z(ICON),
                    hsla(if on { theme.text } else { theme.text_muted }),
                ))
        };
        Some(
            div()
                .flex()
                .items_center()
                .gap(self.z(2.0))
                .child(toggle(
                    IconName::Hash,
                    "Instruction Bytes",
                    layers.bytes,
                    |l| l.bytes = !l.bytes,
                    cx,
                ))
                .child(toggle(
                    IconName::Binary,
                    "Untyped Bytes as Hex",
                    layers.hex,
                    |l| l.hex = !l.hex,
                    cx,
                ))
                .child(toggle(
                    IconName::Layers,
                    "File Structure",
                    layers.structure,
                    |l| l.structure = !l.structure,
                    cx,
                ))
                .into_any_element(),
        )
    }

    /// A section card's strip: what the section holds from its start to
    /// its end, each run of one kind in its colour (the hex view's), what
    /// has none in the track's.
    fn strip_bar(&self, strip: &[Kind]) -> AnyElement {
        let theme = self.theme;
        div()
            .flex_none()
            .flex()
            .w(self.z(STRIP_WIDTH))
            .h(self.z(6.0))
            .mr(self.z(12.0))
            .rounded(self.z(2.0))
            .overflow_hidden()
            .bg(hsla(theme.border_variant))
            .children(strip.chunk_by(|a, b| a == b).map(|run| {
                let color = run.first().and_then(|&k| kind_color(theme, k));
                div()
                    .h_full()
                    .flex_basis(px(0.0))
                    .flex_grow(f(run.len() as u64))
                    .when_some(color, |d, c| d.bg(hsla(c)))
            }))
            .into_any_element()
    }

    /// Pane `id`'s overview, left of its scrollbar: the rows' kinds from
    /// the first to the last in the hex view's colours, the rows on
    /// screen framed; a press scrolls there.
    fn unified_minimap(
        &self,
        id: PaneId,
        flat: &Flat,
        visible: u64,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        let theme = self.theme;
        let state = self.panes.get(&id)?;
        let height = f32::from(state.bounds.get().size.height);
        let total = flat.len() as u64;
        if total == 0 || height <= 0.0 {
            return None;
        }
        let share = |rows: u64| f(rows) / f(total) * height;
        let anchor = state.unified.scroll.anchor;
        let top = share(anchor.line);
        let shown = share(visible.min(total)).max(3.0);
        let column = div()
            .id(("unified-overview", id.0))
            .absolute()
            .top_0()
            .bottom_0()
            .right(self.z(SCROLLBAR))
            .w(self.z(MINIMAP))
            .flex()
            .flex_col()
            .border_l_1()
            .border_color(hsla(theme.border_variant))
            .children(flat.overview.chunk_by(|a, b| a == b).map(|run| {
                let color = run
                    .first()
                    .copied()
                    .flatten()
                    .and_then(|k| kind_color(theme, k));
                div()
                    .w_full()
                    .flex_basis(px(0.0))
                    .flex_grow(f(run.len() as u64))
                    .when_some(color, |d, c| d.bg(hsla(with_alpha(c, 0xb0))))
            }))
            .child(
                div()
                    .absolute()
                    .left_0()
                    .right_0()
                    .top(px(top))
                    .h(px(shown))
                    .border_1()
                    .border_color(hsla(theme.text))
                    .bg(hsla(with_alpha(theme.text, 0x30))),
            )
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, e: &MouseDownEvent, _, cx| {
                    cx.stop_propagation();
                    let Some(state) = this.panes.get_mut(&id) else {
                        return;
                    };
                    let b = state.bounds.get();
                    let at = f32::from(e.position.y - b.origin.y) / f32::from(b.size.height);
                    let total = state.unified.flat.as_ref().map_or(0, |f| f.len() as u64);
                    // The row pressed in the middle of the view.
                    #[expect(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        clippy::cast_precision_loss,
                        reason = "a row from a fraction of the rows"
                    )]
                    let row = (f64::from(at.clamp(0.0, 1.0)) * total as f64) as u64;
                    let scroll = &mut state.unified.scroll;
                    scroll.smooth.stop();
                    scroll.anchor.focus(row, total, visible);
                    cx.notify();
                }),
            );
        Some(column.into_any_element())
    }

    /// The branch arrows of the functions with rows in `shown` of pane
    /// `id` (the listing's arrows, their lines mapped to the rows showing
    /// them: [`Document::arrows`]), in the arrow gutter from `left`: its right
    /// edge at a function line's text. Those with an end on the cursor's
    /// row at full strength.
    fn unified_arrows(
        &self,
        id: PaneId,
        (sources, flat): (&Sources, &Flat),
        shown: std::ops::Range<usize>,
        left: f32,
    ) -> Option<AnyElement> {
        let theme = self.theme;
        let u = &self.panes.get(&id)?.unified;
        self.unified.stubs.borrow_mut().remove(&id);
        let (doc, listing, image, overlays) = sources;
        let (arrows, addresses): (Vec<Arrow>, Vec<(u64, u64)>) = doc
            .arrows(flat, shown, listing, image, overlays)
            .into_iter()
            .unzip();
        if arrows.is_empty() {
            return None;
        }
        let row_h = self.row(self.settings.listing_line_height);
        let rows = self.rows(id, self.settings.listing_line_height);
        let cw = self.char_width.unwrap_or(8.0);
        let g = Geometry {
            width: self.gutter_width(),
            lane: self.row(LANE),
            gap: self.row(GAP),
            lanes: usize::try_from(self.settings.arrow_lanes).unwrap_or(usize::MAX),
            row: row_h,
            height: f(rows) * row_h,
            first: u.scroll.anchor.line,
            offset: u.scroll.anchor.offset,
            label_char: cw * LABEL_SCALE,
            stubs: StubStyle::Leading,
        };
        let cursor = u.cursor as u64;
        // A stub has no words (its operand names where a jump goes, its
        // block's chip where one comes from): its tail leads the way to
        // the other end; the pointer on it peeks there, a press goes there.
        let drawn = arrows::lay_out(
            &g,
            &arrows,
            &theme.arrows(),
            arrows::dim(theme.dark),
            |a| a.from == cursor || a.to == cursor,
            |_, _, _| String::new(),
        );
        let ends = arrows
            .iter()
            .zip(addresses)
            .filter(|(a, _)| arrows::lane_of(a, g.lanes).is_none())
            .map(|(a, ends)| ((a.from, a.to), ends))
            .collect();
        self.unified.stubs.borrow_mut().insert(
            id,
            Stubs {
                left,
                hits: drawn.hits,
                ends,
            },
        );
        Some(
            div()
                .absolute()
                .top_0()
                .left(px(left))
                .w(px(g.width))
                .h_full()
                .child(arrows::paint(drawn.quads))
                .into_any_element(),
        )
    }

    /// A run of the code font, bold if `bold`.
    fn unified_run(&self, len: usize, color: u32, bold: bool) -> TextRun {
        let mut run = self.text_run(len, color, None);
        if bold {
            run.font.weight = FontWeight::SEMIBOLD;
        }
        run
    }

    /// `parts` as one styled text.
    fn unified_text(&self, parts: Vec<Part>) -> StyledText {
        self.unified_text_lit(parts, &[], &[])
    }

    /// `parts` as one styled text, the parts `lit` on the highlight, the
    /// find bar's `marks` (bytes of the text) on theirs.
    fn unified_text_lit(
        &self,
        parts: Vec<Part>,
        lit: &[usize],
        marks: &[(std::ops::Range<usize>, u32)],
    ) -> StyledText {
        let mut text = String::new();
        let mut runs = Vec::with_capacity(parts.len());
        for (i, (part, color, bold)) in parts.into_iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            let mut run = self.unified_run(part.len(), color, bold);
            if lit.contains(&i) {
                run.background_color = Some(hsla(self.theme.search_match));
            }
            runs.push(run);
            text.push_str(&part);
        }
        StyledText::new(text).with_runs(marked(runs, marks))
    }

    /// Pane `id`'s unified listing.
    #[expect(clippy::too_many_lines, reason = "one row of each kind")]
    pub fn render_unified(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let row_h = self.row(self.settings.listing_line_height);
        let visible = self.rows(id, self.settings.listing_line_height);
        let focused = self.layout.focused() == id;
        self.char_width(window);
        self.harvest_signatures();
        let sources = self.unified_sources();
        let flat = sources
            .as_ref()
            .and_then(|sources| self.unified_flat(id, sources));
        if let (Some(sources), Some(flat)) = (&sources, &flat) {
            self.unified_follow(id, sources, flat);
        }
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        let bounds = Rc::clone(&state.bounds);
        let commenting = self.comment.as_ref().is_some_and(|c| c.pane == id);
        let pane = div()
            .id(("unified", id.0))
            .key_context(if commenting { "CEdit" } else { "Code" })
            .track_focus(&state.focus)
            .size_full()
            .relative()
            .overflow_hidden()
            .bg(hsla(theme.editor))
            .rounded_b(self.island_corner())
            .font_family(self.settings.code_font.clone())
            .font_features(self.font_features())
            .text_size(px(self.code_size()))
            .line_height(px(row_h))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.unified_down(id, e, window, cx);
                }),
            )
            .on_mouse_down(
                MouseButton::Middle,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.unified_down(id, e, window, cx);
                }),
            )
            .on_mouse_move(cx.listener(move |this, e: &MouseMoveEvent, window, cx| {
                this.unified_move(id, e, window, cx);
            }))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _, _, _| {
                    this.scrollbar_drag = None;
                    for state in this.panes.values_mut() {
                        state.unified.selection.release();
                    }
                }),
            )
            .on_key_down(cx.listener(move |this, e: &KeyDownEvent, _, cx| {
                if this.unified_key(id, e) {
                    cx.stop_propagation();
                    cx.notify();
                }
            }))
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| this.wheel(id, e, cx)))
            .when(commenting, |d| {
                // A click outside the pane drops the field (inside, the
                // click itself does).
                d.on_mouse_down_out(cx.listener(|this, _, window, cx| {
                    this.close_overlays(window, cx);
                    cx.notify();
                }))
            })
            .child(measured(bounds).absolute().size_full());
        let (Some(sources), Some(flat)) = (sources, flat) else {
            return pane.into_any_element();
        };
        let Some(ctx) = self.rows_ctx(id, &sources) else {
            return pane.into_any_element();
        };
        let listing = &sources.1;
        let u = &state.unified;
        let cols = ctx.cols;
        let cw = cols.cw;
        let first = usize::try_from(u.scroll.anchor.line).unwrap_or(0);
        let offset = u.scroll.anchor.offset;
        let end = first
            .saturating_add(usize::try_from(visible).unwrap_or(0) + 1)
            .min(flat.len());
        let muted = theme.text_muted;
        let quiet = theme.text_placeholder;
        // The rows selected.
        let selected = u.selection.range(u.cursor as u64);
        let mut field_box = None;
        let mut rows: Vec<AnyElement> = Vec::with_capacity(end.saturating_sub(first));
        // The headers (cards, blocks), drawn over the arrows: a lane stops
        // at a header's edge and goes on past it.
        let mut headers: Vec<AnyElement> = Vec::new();
        // The headers holding the first row, pinned at the top over all.
        let pinned = flat.pinned(first);
        let mut stuck: Vec<AnyElement> = Vec::new();
        // The rows on screen, each at its place: with the comment field
        // open, its item's further comment lines go (the field writes
        // them) and the rows below move by the lines it takes.
        let commented = ctx.field.map(|(edit, at, _)| {
            let lines = listing.comment_lines(at);
            (at, lines, edit.field.lines() as u64)
        });
        let line_of_row = |k: usize| match flat.rows.get(k).map(|r| &r.kind) {
            Some(RowKind::Line(n)) => Some(*n),
            _ => None,
        };
        let mut entries: Vec<(usize, f32, bool)> = Vec::with_capacity(end - first + pinned.len());
        let mut top = -offset;
        let mut next = first;
        while next < flat.len() && top < f(visible) * row_h {
            let line = line_of_row(next);
            let taken = match (&commented, line) {
                (Some((at, lines, _)), Some(n)) if n != *at && lines.contains(&n) => 0,
                (Some((at, _, field_lines)), Some(n)) if n == *at => *field_lines,
                _ => 1,
            };
            if taken > 0 {
                entries.push((next, top, false));
                top += f(taken) * row_h;
            }
            next += 1;
        }
        let end = next;
        entries.extend(
            pinned
                .iter()
                .enumerate()
                .map(|(i, &k)| (k, f(i as u64) * row_h, true)),
        );
        let last_pinned = pinned.last().copied();
        for (k, y, is_pinned) in entries {
            let Some(row) = flat.rows.get(k) else {
                break;
            };
            let Some(v) = self.row_view(&ctx, row) else {
                continue;
            };
            if k == u.cursor
                && let Some(column) = v.type_column
            {
                let x = v.start + f(column as u64) * cw;
                self.unified.type_x.set(Some((id, k, x)));
            }
            if let (Some(column), Some((edit, ..))) = (v.comment_column, ctx.field) {
                let x = v.start + f(column as u64) * cw;
                field_box = Some(self.comment_box(edit, x, y, row_h));
            }
            let RowView {
                place: (place, place_color),
                bytes,
                byte_marks,
                start,
                parts,
                lit,
                marks,
                meta,
                fold,
                inline_fold,
                header,
                loop_head,
                xrefs,
                snippet,
                kind,
                linked_wash,
                tint,
                strip,
                ..
            } = v;
            // Where a jump landed, fading.
            let landing = u
                .landed
                .filter(|&(row, at)| row == k && at.elapsed() < LANDING)
                .map(|(_, at)| {
                    let left = 1.0 - at.elapsed().as_secs_f32() / LANDING.as_secs_f32();
                    let full = f32::from(u8::try_from(theme.active_match & 0xff).unwrap_or(0));
                    #[expect(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        reason = "an alpha within 0..=255"
                    )]
                    let alpha = (left.clamp(0.0, 1.0) * full).round() as u8;
                    with_alpha(theme.active_match, alpha)
                });
            if landing.is_some() {
                window.request_animation_frame();
            }
            let background = if let Some(landing) = landing {
                Some(landing)
            } else if k == u.cursor {
                Some(if focused {
                    theme.active_line
                } else {
                    theme.lit()
                })
            } else if selected.as_ref().is_some_and(|r| r.contains(&(k as u64))) {
                Some(theme.selection)
            } else if let Some(wash) = linked_wash {
                Some(wash)
            } else if header == Header::Item {
                Some(theme.tab_bar)
            } else {
                None
            };
            let chevron = |open: bool| {
                icon(
                    if open {
                        IconName::ChevronDown
                    } else {
                        IconName::ChevronRight
                    },
                    self.z(ICON - 2.0),
                    hsla(muted),
                )
            };
            let at = |x: f32| {
                div()
                    .absolute()
                    .top_0()
                    .bottom_0()
                    .left(px(x))
                    .flex()
                    .items_center()
            };
            let badge = xrefs.filter(|chips| !chips.is_empty()).map(|chips| {
                let quiet = header == Header::Block && !loop_head;
                self.xref_badge(chips, (k, row_h), quiet, cx)
            });
            let stripe = kind.and_then(|k| kind_color(theme, k));
            let rule = match header {
                Header::Item | Header::Piece => Some(theme.border_variant),
                Header::Block if loop_head => Some(with_alpha(theme.border_variant, 0x70)),
                Header::Block | Header::None => None,
            };
            // A card is opaque, its own wash (the cursor's, a card's) over
            // the pane's colour; a block's header masks the arrows only
            // behind what it says, in the colour it shows there.
            let card = matches!(header, Header::Item | Header::Piece);
            let (base, wash) = if card || is_pinned {
                (Some(theme.editor), background)
            } else {
                (background, None)
            };
            let mask = (header == Header::Block).then(|| {
                let editor = solid(theme.editor);
                background.map_or(editor, |b| over(b, editor))
            });
            let element = div()
                .absolute()
                .top(px(y))
                .left_0()
                .right(self.z(SCROLLBAR + MINIMAP))
                .h(px(row_h))
                .whitespace_nowrap()
                .overflow_hidden()
                .when_some(base, |d, b| d.bg(hsla(b)))
                .when_some(wash, |d, w| {
                    d.child(div().absolute().size_full().bg(hsla(w)))
                })
                .when_some(rule, |d, c| d.border_t_1().border_color(hsla(c)))
                .when_some(stripe, |d, color| {
                    d.child(
                        div()
                            .absolute()
                            .left_0()
                            .top_0()
                            .bottom_0()
                            .w(self.z(3.0))
                            .bg(hsla(color)),
                    )
                })
                .when_some(fold, |d, open| d.child(at(cols.fold).child(chevron(open))))
                .child(
                    at(cols.address)
                        .w(px(cols.bytes - cols.address - cw * 0.5))
                        .when_some(tint, |d, t| d.bg(hsla(t)))
                        .text_color(hsla(place_color))
                        .child(place),
                )
                .when_some(bytes, |d, bytes| {
                    d.child(
                        at(cols.bytes)
                            .w(px(cols.marks - cols.bytes))
                            .overflow_hidden()
                            .child(self.unified_text_lit(bytes, &[], &byte_marks)),
                    )
                })
                .when_some(inline_fold, |d, open| {
                    d.child(at(start - 2.0 * cw).child(chevron(open)))
                })
                .child(
                    at(start)
                        .right_0()
                        .child(
                            div()
                                .flex_none()
                                .flex()
                                .items_center()
                                .h_full()
                                .when_some(mask, |d, m| d.bg(hsla(m)).pr(self.z(4.0)))
                                .child(
                                    div()
                                        .flex_none()
                                        .child(self.unified_text_lit(parts, &lit, &marks)),
                                )
                                .children(badge)
                                .when(!snippet.is_empty(), |d| {
                                    d.child(
                                        div()
                                            .flex_none()
                                            .ml(self.z(12.0))
                                            .child(self.unified_text(snippet)),
                                    )
                                }),
                        )
                        .child(div().flex_1().min_w(px(2.0 * cw)))
                        .children(strip.map(|s| self.strip_bar(s)))
                        .when_some(meta, |d, meta| {
                            d.child(
                                div()
                                    .flex_none()
                                    .pr(self.z(10.0))
                                    .text_color(hsla(quiet))
                                    .child(meta),
                            )
                        }),
                );
            // The last pinned header closes the stack.
            let element = element.when(is_pinned && last_pinned == Some(k), |d| {
                d.border_b_1().border_color(hsla(theme.border))
            });
            if is_pinned {
                stuck.push(element.into_any_element());
            } else if header != Header::None {
                headers.push(element.into_any_element());
            } else {
                rows.push(element.into_any_element());
            }
        }
        let total = flat.len() as u64;
        let bar = self.scrollbar(id, total, u.cursor as u64, u.scroll.anchor, visible);
        let arrows = self.unified_arrows(id, (&sources, &flat), first..end, cols.marks);
        let minimap = self.unified_minimap(id, &flat, visible, cx);
        pane.children(rows)
            .children(arrows)
            .children(headers)
            .children(field_box)
            .children(stuck)
            .children(minimap)
            .child(bar)
            .into_any_element()
    }
}
