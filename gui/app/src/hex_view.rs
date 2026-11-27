//! A listing pane shown as the structured hex view (the pane's view
//! toggle beside text and graph): the usual hex-dump layout (the
//! prefix, 16 bytes in two groups of 8, the characters; uppercase hex) in
//! the listing's font, one line a row; each byte tinted by what it is
//! (quiet One tokens; zeros muted), a hairline where an item starts; a
//! typed overlay's fields tinted instead, neighbours alternating through
//! the players' colours, the field under the cursor outlined, a card on
//! hover with the field's path, type and value, the byte under the pointer
//! lit in both columns; the selection a range of
//! bytes, synced with the shared cursor; the overview strip in place of
//! the scrollbar (the whole image by kind or entropy). Each hex pane has
//! its own side area, the structure tree (every overlay a root) over the
//! data inspector: right of the bytes when the pane is wide enough for
//! both, else under them in a split whose divider drags; hidden only by
//! its toolbar's toggle. `Alt+Q` lays a C type over the cursor, saved
//! beside the project.

use std::cell::Cell;
use std::collections::HashMap;
use std::ops::Range;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use binbun::Database;
use binbun::decompile::Callers;
use binbun_gui_view::Stage;
use binbun_gui_view::collab::Cursor;
use binbun_gui_view::commands::{Command, Facts};
use binbun_gui_view::feature_map::{band, runs};
use binbun_gui_view::hex::{
    Anchor, Cell as ByteCell, Columns, CopyFormat, HexImage, Kind, Mode, Overlay, Placed, ROW,
    SidePlace, SideSplit, Source, copy_text, debug_overlays, load_overlays, save_overlays,
    user_overlay,
};
use binbun_gui_view::hex_globals::{self, Global, ProgramGlobals, layered};
use binbun_gui_view::hex_tree::{self, Key, Line as TreeLine, Move, StructTree};
use binbun_gui_view::hex_types::{TypeSet, read_uint};
use binbun_gui_view::inspect::{self, Values};
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::scroll::{ScrollAnchor, Wheel};
use binbun_gui_view::settype::TypeField as SetTypeField;
use gpui_kit::assets::IconName;
use gpui_kit::base::Input as FieldInput;
use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Bounds, ClickEvent, ClipboardItem, Context, Entity, FocusHandle, KeyDownEvent,
    MouseButton, MouseDownEvent, MouseMoveEvent, Pixels, Point, ScrollEvent, StyledText,
    Subscription, TextRun, Window, canvas, div, fill, point, px, size,
};

use crate::collab::TickStyle;
use crate::icons::icon;
use crate::listing_view::{SCROLLBAR, column};
use crate::panes::measured;
use crate::scrolling::{scrolled, wheel};
use crate::selection::select_lines;
use crate::theme::{Theme, hsla, solid, with_alpha};
use crate::type_field::Place;
use crate::workspace::{EdgeDrag, ICON, ICON_BUTTON, TOOLBAR_PAD, TabKind, Workspace, f, rows_in};

/// The side area's width (logical).
const SIDE_WIDTH: f32 = 520.0;
/// The least height of the bytes and of the side area under them while
/// their divider is dragged (logical).
const SIDE_MIN: f32 = 120.0;
/// The structure tree's references column's width (logical).
const REFS_WIDTH: f32 = 40.0;
/// The overview's parts (each a band of the strip).
const BUCKETS: usize = 512;
/// The left margin of the rows (logical).
const MARGIN: f32 = 10.0;
/// The alpha of a byte's tint, and of the overview's bands.
const TINT: u8 = 0x26;
pub(crate) const BAND: u8 = 0xb0;
/// Bytes read for the inspector (its strings' limit and more).
const INSPECTED: u64 = 80;
/// Bytes copied at most.
const COPIED: u64 = 1 << 20;

/// A space summarised for the overview strip: each band's kind and
/// entropy (the feature map's colours too).
pub(crate) type Overview = Arc<Vec<(Kind, f32)>>;

/// What the overview strip's bands are drawn from besides the overview:
/// by entropy or not, the strip's height and width, the theme.
#[derive(Clone, Copy, PartialEq)]
struct BandsKey {
    entropy: bool,
    height: f32,
    width: f32,
    theme: *const Theme,
}

/// The field where a C type is typed to lay over the bytes.
pub struct TypeField {
    /// The pane.
    pub pane: PaneId,
    /// Where the type goes.
    pub anchor: Anchor,
    /// The input.
    pub input: Entity<InputState>,
    /// Why the text is refused, if it is.
    pub error: Option<String>,
    _subs: [Subscription; 2],
}

/// The hex views' shared state: the byte space of the open binary, the
/// overlays, the C types, the overview, the apply-type field.
#[derive(Default)]
pub struct HexUi {
    /// The binary it is for and its byte space.
    image: Option<(PathBuf, Arc<HexImage>)>,
    /// The headers' and user's C types.
    types: Option<TypeSet>,
    /// The user's overlays.
    user: Vec<Overlay>,
    /// The debug information's (none yet: the database is not here).
    debug: Option<Vec<Overlay>>,
    /// The whole program's typed globals, once its table is known.
    program: ProgramGlobals,
    /// The table they are from (another one is read again).
    program_table: Option<Weak<Callers>>,
    /// Every overlay, weakest first: headers, the whole program's typed
    /// globals, debug information's, the user's.
    overlays: Arc<Vec<Overlay>>,
    /// The overlays changed: rebuild them and their rows.
    dirty: bool,
    /// The overview of each space, for the analysis shown (forgotten when
    /// another lands: [`HexUi::forget_overview`]).
    overview: HashMap<Mode, Overview>,
    /// The overview strip's bands as last drawn, with what they were made
    /// from: built once per overview and size, a run of bands of one
    /// colour one quad.
    bands: Option<(Overview, BandsKey, Arc<Vec<Quad>>)>,
    /// The apply-type field, when open.
    pub field: Option<TypeField>,
    /// When the last frame of a wheel's easing was drawn.
    frame_at: Option<Instant>,
    /// Each hex pane's side area as drawn.
    sides: HashMap<PaneId, Side>,
    /// The field under the pointer, for its card: its pane, where the
    /// pointer is (in the window), the overlay's index and the leaf.
    hover: Option<(PaneId, Point<Pixels>, Placed)>,
    /// The byte under the pointer, lit in both columns: its pane and where
    /// it is.
    hover_byte: Option<(PaneId, u64)>,
}

/// A hex pane's side area as drawn (its state is the pane's
/// [`HexPane`](binbun_gui_view::hex::HexPane)'s).
#[derive(Default)]
struct Side {
    /// The pane's whole area, as last drawn (whether the side area fits).
    pane: Rc<Cell<Bounds<Pixels>>>,
    /// The structure tree's lines as shown, until it or the overlays
    /// change.
    lines: Option<Arc<Vec<TreeLine>>>,
    /// The tree's rows' area, as last drawn.
    bounds: Rc<Cell<Bounds<Pixels>>>,
    /// The tree's focus (its keys).
    focus: Option<FocusHandle>,
    /// The tree's selected row is brought into view when next drawn.
    reveal: bool,
}

/// A filled rectangle, relative to the pane.
#[derive(Clone, Copy, Debug)]
struct Quad {
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    color: u32,
}

/// How a moved cursor is brought into view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reveal {
    /// As a jump's target: on the third row.
    Jump,
    /// Keys: with a sixth of the rows around it.
    Keys,
    /// The pointer: only scrolled if off screen.
    Pointer,
}

impl HexUi {
    /// Forgets the overviews: another analysis landed (kinds may differ).
    pub fn forget_overview(&mut self) {
        self.overview.clear();
    }
}

/// The colour a kind's bytes are tinted with, if any.
pub(crate) fn kind_color(theme: &Theme, kind: Kind) -> Option<u32> {
    match kind {
        Kind::Header => Some(theme.keyword),
        Kind::Table => Some(theme.type_),
        Kind::Code => Some(theme.function),
        Kind::LooseCode => Some(theme.parameter),
        Kind::String => Some(theme.string),
        Kind::Pointer => Some(theme.constant),
        Kind::Import => Some(theme.hint),
        Kind::Value => Some(theme.number),
        Kind::Relocation => Some(theme.punctuation_special),
        Kind::Section => Some(theme.comment_doc),
        Kind::Padding | Kind::Unexplored | Kind::Other | Kind::Uninitialised | Kind::Gap => None,
    }
}

/// The tint of an overlay's leaf `ordinal`: the players' colours in turn,
/// so neighbours differ.
fn leaf_tint(theme: &Theme, ordinal: u64) -> u32 {
    theme.tint(u8::try_from(ordinal % 4).unwrap_or(0))
}

/// A 1 px outline of the rectangle `(x, y, w, h)` in `color`: its top and
/// bottom, and its left and right sides where `sides` says.
fn frame((x, y, w, h): (f32, f32, f32, f32), sides: (bool, bool), color: u32) -> Vec<Quad> {
    let mut quads = vec![
        Quad {
            x,
            y,
            w,
            h: 1.0,
            color,
        },
        Quad {
            x,
            y: y + h - 1.0,
            w,
            h: 1.0,
            color,
        },
    ];
    if sides.0 {
        quads.push(Quad {
            x,
            y,
            w: 1.0,
            h,
            color,
        });
    }
    if sides.1 {
        quads.push(Quad {
            x: x + w - 1.0,
            y,
            w: 1.0,
            h,
            color,
        });
    }
    quads
}

impl Workspace {
    /// Whether pane `id` shows its listing as the hex view.
    pub fn shows_hex(&self, id: PaneId) -> bool {
        matches!(self.layout.active(id), Some(TabKind::Listing))
            && self.panes.get(&id).is_some_and(|s| s.hex.on)
    }

    /// The byte space, made (and the overlays read) once the image is
    /// parsed.
    pub fn ensure_hex(&mut self) {
        let Some(session) = &self.session else {
            return;
        };
        let Some((bytes, image)) = session.loaded() else {
            return;
        };
        let path = session.path().to_path_buf();
        let ui = &mut self.hex;
        if ui.image.as_ref().is_none_or(|(p, _)| *p != path) {
            let hex = HexImage::new(bytes, image);
            let mut types = TypeSet::builtin(hex.model());
            let loaded = session
                .project()
                .map(|project| load_overlays(&project.overlays(), &mut types));
            let user = match loaded {
                Some(Ok(user)) => user,
                Some(Err(error)) => {
                    self.error = Some(error);
                    Vec::new()
                }
                None => Vec::new(),
            };
            ui.image = Some((path, Arc::new(hex)));
            ui.types = Some(types);
            ui.user = user;
            ui.debug = None;
            ui.program = ProgramGlobals::default();
            ui.program_table = None;
            ui.overview.clear();
            ui.field = None;
            ui.dirty = true;
        }
        if ui.debug.is_none()
            && let Some(db) = session.database()
        {
            ui.debug = Some(
                db.debug()
                    .map(|d| debug_overlays(d.model()))
                    .unwrap_or_default(),
            );
            ui.dirty = true;
        }
        // The whole program's typed globals, once the callers pass is
        // known, read again from each table found after it (a type edit).
        let mut relayer = false;
        if let (Some(db), Some((_, hex)), true) = (
            session.database(),
            ui.image.as_ref(),
            self.stage >= Stage::Callers,
        ) && let Some(callers) = db.known_callers(&[])
            && ui
                .program_table
                .as_ref()
                .and_then(Weak::upgrade)
                .is_none_or(|known| !Arc::ptr_eq(&known, &callers))
        {
            let globals = callers
                .schemes
                .globals()
                .iter()
                .filter(|&(start, _)| hex.holds(Mode::Address, start))
                .map(|(start, ty)| Global {
                    start,
                    size: ty.size,
                    name: session.global_name(start),
                })
                .collect();
            let before = ui.program.globals().len();
            ui.program = ProgramGlobals::new(globals, ui.debug.as_deref().unwrap_or_default());
            ui.program_table = Some(Arc::downgrade(&callers));
            // The same globals retyped keep the trees' state.
            ui.dirty |= ui.program.globals().len() != before;
            relayer = true;
        }
        if ui.dirty {
            ui.dirty = false;
            relayer = true;
            for state in self.panes.values_mut() {
                state.hex.tree = StructTree::default();
                state.hex.tree_top = 0;
            }
        }
        if relayer {
            self.relayer();
        }
    }

    /// The overlays made again (a global laid out, the table read again,
    /// an overlay added), the trees' lines with them.
    fn relayer(&mut self) {
        let ui = &mut self.hex;
        let headers = ui.image.as_ref().map_or(&[][..], |(_, h)| h.headers());
        ui.overlays = Arc::new(layered(
            headers,
            ui.program.overlays(),
            ui.debug.as_deref().unwrap_or_default(),
            &ui.user,
        ));
        ui.hover = None;
        for side in ui.sides.values_mut() {
            side.lines = None;
        }
    }

    /// Lays out the whole program's globals `wanted` (indices) not laid
    /// out yet; the overlays made again if any was; whether any was.
    fn lay_out_globals(&mut self, wanted: Vec<usize>) -> bool {
        let Some(session) = &self.session else {
            return false;
        };
        let laid = self
            .hex
            .program
            .lay_out(wanted, |start| session.global_table(start));
        if laid {
            self.relayer();
        }
        laid
    }

    /// Lays out every one of the whole program's globals not laid out yet
    /// (the unified listing shows them all); whether any was.
    pub(crate) fn lay_out_all_globals(&mut self) -> bool {
        let n = self.hex.program.globals().len();
        self.lay_out_globals((0..n).collect())
    }

    /// The user renamed something: the globals' names again.
    pub fn hex_renamed(&mut self) {
        let Some(session) = &self.session else {
            return;
        };
        if self.hex.program.rename(|start| session.global_name(start)) {
            self.relayer();
        }
    }

    /// The byte space, if the image is parsed.
    pub(crate) fn hex_image(&self) -> Option<Arc<HexImage>> {
        self.hex.image.as_ref().map(|(_, h)| Arc::clone(h))
    }

    /// The overlays: the headers', the typed globals', the user's.
    pub(crate) fn hex_overlays(&self) -> Arc<Vec<Overlay>> {
        Arc::clone(&self.hex.overlays)
    }

    /// The overview of `mode`.
    pub(crate) fn hex_overview(&mut self, image: &HexImage, mode: Mode) -> Option<Overview> {
        let listing = self.listing.clone();
        if let Some(overview) = self.hex.overview.get(&mode) {
            return Some(Arc::clone(overview));
        }
        let (bytes, _) = self.session.as_ref()?.loaded()?;
        let started = Instant::now();
        let overview =
            Arc::new(image.overview(bytes, listing.as_ref().map(|l| l.lines()), mode, BUCKETS));
        trace!(
            "hex overview {mode:?}: {:.1} ms",
            started.elapsed().as_secs_f64() * 1e3
        );
        self.hex.overview.insert(mode, Arc::clone(&overview));
        Some(overview)
    }

    /// The address of the first byte of pane `id`'s hex selection.
    pub fn hex_address(&self, id: PaneId) -> Option<u64> {
        let image = self.hex.image.as_ref().map(|(_, h)| h)?;
        let hex = &self.panes.get(&id)?.hex;
        image.address_of(hex.selection().start, hex.mode)
    }

    /// Pane `id`'s hex selection of more than its cursor, as addresses:
    /// the first, past the last, and whether the cursor is at the first.
    pub fn hex_bytes(&self, id: PaneId) -> Option<(u64, u64, bool)> {
        let image = self.hex.image.as_ref().map(|(_, h)| h)?;
        let hex = &self.panes.get(&id)?.hex;
        hex.anchor?;
        let bytes = hex.selection();
        let start = image.address_of(bytes.start, hex.mode)?;
        let last = image.address_of(bytes.end.checked_sub(1)?, hex.mode)?;
        Some((
            start,
            last + 1,
            hex.cursor == bytes.start && bytes.end - bytes.start > 1,
        ))
    }

    /// Pane `id`'s hex view selects `bytes` (as [`Self::hex_bytes`] says
    /// them), the cursor at the same end; none drops its selection.
    pub fn hex_take(&mut self, id: PaneId, bytes: Option<(u64, u64, bool)>) {
        let image = self.hex_image();
        let Some(hex) = self.panes.get_mut(&id).map(|s| &mut s.hex) else {
            return;
        };
        let convert = |at: u64| image.as_ref()?.convert(at, Mode::Address, hex.mode);
        let Some((start, end, at_start)) = bytes else {
            hex.anchor = None;
            return;
        };
        let (Some(first), Some(last)) = (convert(start), convert(end.saturating_sub(1))) else {
            return;
        };
        (hex.cursor, hex.anchor) = if at_start {
            (first, Some(last))
        } else {
            (last, Some(first))
        };
        hex.target = None;
    }

    /// The commands' facts of the hex view.
    pub fn hex_facts(&self) -> Facts {
        let id = self.layout.focused();
        let shown = self.shows_hex(id);
        let hex = self.panes.get(&id).map(|s| &s.hex);
        Facts {
            hex: shown,
            file_offsets: shown && hex.is_some_and(|h| h.mode == Mode::File),
            entropy: hex.is_some_and(|h| h.entropy),
            hex_side: hex.is_some_and(|h| !h.side_hidden),
            user_type: self.user_overlay_at(id).is_some(),
            ..Facts::default()
        }
    }

    /// Pane `id`'s byte cursor and the bytes it selects (in its space): the
    /// hex view's, else the unified listing's rows' (their first byte the
    /// cursor); none in other views.
    fn pane_byte_range(&self, id: PaneId) -> Option<(Mode, u64, Range<u64>)> {
        if self.shows_unified(id) {
            let (mode, bytes) = self.unified_byte_range(id)?;
            let cursor = self.unified_place(id)?.1;
            return Some((mode, cursor, bytes));
        }
        let hex = &self.panes.get(&id).filter(|_| self.shows_hex(id))?.hex;
        Some((hex.mode, hex.cursor, hex.selection()))
    }

    /// The index in the user's overlays of the one holding pane `id`'s
    /// byte cursor.
    fn user_overlay_at(&self, id: PaneId) -> Option<usize> {
        let image = self.hex.image.as_ref().map(|(_, h)| h)?;
        let (mode, cursor, _) = self.pane_byte_range(id)?;
        self.hex
            .user
            .iter()
            .rposition(|o| image.locate(o, mode, cursor).is_some())
    }

    /// Removes the user's type holding pane `id`'s byte cursor.
    pub(crate) fn remove_user_type(&mut self, id: PaneId) {
        if let Some(k) = self.user_overlay_at(id) {
            self.hex.user.remove(k);
            self.hex.dirty = true;
            self.save_user_overlays();
        }
    }

    /// Runs `command` where the hex view takes it; whether it did.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "the hex view takes a few of the registry's commands; `run` the rest"
    )]
    pub fn hex_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let id = self.layout.focused();
        if command == Command::Back && self.hex.field.is_some() {
            self.close_type_field(window, cx);
            return true;
        }
        match command {
            Command::ToggleHex => {
                if self.shows_hex(id) {
                    self.leave_hex(id);
                } else {
                    // In the listing's pane, beside the C, never over it.
                    self.show_in_hex(window, cx);
                }
                return true;
            }
            Command::ShowInHex => {
                self.show_in_hex(window, cx);
                return true;
            }
            _ if !self.shows_hex(id) => return false,
            _ => {}
        }
        if let Some(taken) = self.tree_command(id, command, window, cx) {
            return taken;
        }
        let Some(image) = self.hex_image() else {
            return false;
        };
        let visible = self.rows(id, self.settings.listing_line_height);
        let Some(hex) = self.panes.get(&id).map(|s| &s.hex) else {
            return false;
        };
        let (mode, cursor) = (hex.mode, hex.cursor);
        let page = i64::try_from(visible.saturating_sub(2).max(1)).unwrap_or(1) * 16;
        let to = match command {
            Command::MoveUp => Some(image.step(mode, cursor, -16)),
            Command::MoveDown => Some(image.step(mode, cursor, 16)),
            Command::PageUp => Some(image.step(mode, cursor, -page)),
            Command::PageDown => Some(image.step(mode, cursor, page)),
            Command::Top => Some(image.ends(mode).0),
            Command::Bottom => Some(image.ends(mode).1),
            _ => None,
        };
        if let Some(to) = to {
            self.hex_select(id, to, false, Reveal::Keys);
            return true;
        }
        match command {
            Command::ToggleGraph => {
                self.leave_hex(id);
                self.set_graph(id, true);
            }
            Command::CopyName | Command::CopyHex => self.copy_hex(id, CopyFormat::Hex, cx),
            Command::CopyEscaped => self.copy_hex(id, CopyFormat::Bytes, cx),
            Command::CopyCArray => self.copy_hex(id, CopyFormat::CArray, cx),
            Command::HexFileOffsets => {
                if let Some(state) = self.panes.get_mut(&id) {
                    let to = match state.hex.mode {
                        Mode::Address => Mode::File,
                        Mode::File => Mode::Address,
                    };
                    state.hex.switch(&image, to);
                    state.hex.target = None;
                }
                self.reveal_hex(id, Reveal::Jump);
            }
            Command::HexEntropy => {
                if let Some(state) = self.panes.get_mut(&id) {
                    state.hex.entropy = !state.hex.entropy;
                }
            }
            Command::HexSide => {
                if let Some(state) = self.panes.get_mut(&id) {
                    state.hex.side_hidden = !state.hex.side_hidden;
                }
            }
            Command::ApplyType => self.open_type_field(id, window, cx),
            Command::RemoveType => self.remove_user_type(id),
            Command::Follow => {
                let little = image.little();
                let width = u64::from(image.model().pointer);
                let target = self.session.as_ref().and_then(|s| {
                    let (bytes, _) = s.loaded()?;
                    read_uint(&image.read(bytes, mode, cursor..cursor + width), little)
                });
                if let Some(target) = target.filter(|&t| image.holds(Mode::Address, t)) {
                    self.jump(target, cx);
                }
            }
            _ => return false,
        }
        true
    }

    /// Shows pane `id`'s listing as the hex view at the shared cursor
    /// (opening a listing tab there if it shows something else), the
    /// inspector in the right dock.
    pub fn show_hex(&mut self, id: PaneId, window: &mut Window, cx: &mut Context<Self>) {
        let address = self.current_address();
        // The listing's selection, as bytes.
        let bytes = self.pane_bytes(id);
        if !matches!(self.layout.active(id), Some(TabKind::Listing)) {
            self.open_tab(id, TabKind::Listing, window, cx);
        }
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        state.unified.on = false;
        if !state.hex.on {
            state.hex.on = true;
            state.hex.graph = state.graph.on;
            state.graph.on = false;
        }
        state.hex.target = address.map(|a| (a, true));
        state.hex.followed = Some(state.listing.cursor);
        if bytes.is_some() {
            self.hex_take(id, bytes);
        }
    }

    /// Pane `id` back to its listing (or graph) from the hex view, the
    /// cursor kept.
    pub fn leave_hex(&mut self, id: PaneId) {
        let rows = self.rows(id, self.settings.listing_line_height);
        let len = self.listing.as_ref().map_or(0, |l| l.len());
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        if !state.hex.on {
            return;
        }
        state.hex.on = false;
        state.graph.on = state.hex.graph;
        let cursor = state.listing.cursor;
        state
            .listing
            .scroll
            .anchor
            .reveal(cursor, len, rows, rows / 3);
        if self.hex.field.as_ref().is_some_and(|f| f.pane == id) {
            self.hex.field = None;
        }
    }

    /// The cursor's address in a hex view: the focused pane, else another
    /// listing pane, else a listing tab opened in the focused pane.
    fn show_in_hex(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let focused = self.layout.focused();
        let address = self.current_address();
        let listing_pane = |this: &Self| {
            this.layout
                .panes()
                .filter(|p| p.synced)
                .map(|p| p.id)
                .filter(|&p| matches!(this.layout.active(p), Some(TabKind::Listing)))
                .max_by_key(|&p| (this.shows_hex(p), p == focused))
        };
        let id = if matches!(self.layout.active(focused), Some(TabKind::Listing)) {
            focused
        } else {
            listing_pane(self).unwrap_or(focused)
        };
        self.show_hex(id, window, cx);
        if let (Some(address), Some(state)) = (address, self.panes.get_mut(&id)) {
            state.hex.target = Some((address, true));
        }
        self.focus_pane(id, window, cx);
    }

    /// Pane `id`'s hex cursor to `at` (the selection extended if
    /// `extend`), revealed as `how`; the sync group follows.
    fn hex_select(&mut self, id: PaneId, at: u64, extend: bool, how: Reveal) {
        if let Some(state) = self.panes.get_mut(&id) {
            state.hex.select(at, extend);
            state.hex.target = None;
        }
        self.reveal_hex(id, how);
        self.hex_moved(id);
        self.tree_follow(id);
    }

    /// The structure tree follows pane `id`'s cursor: the deepest row
    /// holding its byte selected, the tree expanded to it.
    fn tree_follow(&mut self, id: PaneId) {
        let Some(image) = self.hex_image() else {
            return;
        };
        let Some((mode, cursor)) = self.panes.get(&id).map(|s| (s.hex.mode, s.hex.cursor)) else {
            return;
        };
        let overlays = Arc::clone(&self.hex.overlays);
        let key = overlays.iter().enumerate().rev().find_map(|(k, o)| {
            let offset = image.locate(o, mode, cursor)?;
            hex_tree::deepest(&overlays, k, offset)
        });
        let Some(key) = key else {
            return;
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        if state.hex.tree.selected.as_ref() != Some(&key) {
            state.hex.tree.reveal(&key);
            let side = self.hex.sides.entry(id).or_default();
            side.lines = None;
            side.reveal = true;
        }
    }

    /// The byte under `position` in pane `id`, and its leaf for its card;
    /// whether either changed.
    fn hex_hover(&mut self, id: PaneId, position: Point<Pixels>) -> bool {
        let at = match self.hex_hit(id, position) {
            Some(HexHit::Bytes { line, col }) => self.hex_image().and_then(|image| {
                let mode = self.panes.get(&id)?.hex.mode;
                let columns = Columns {
                    prefix: image.prefix_width(mode),
                };
                if col < columns.prefix + 2 || col >= columns.width() {
                    return None;
                }
                self.hex_position(id, line, col).map(|(at, _)| at)
            }),
            Some(HexHit::Strip(_)) | None => None,
        };
        let placed = at.and_then(|at| {
            let mode = self.panes.get(&id)?.hex.mode;
            self.hex_image()?
                .placed(&self.hex.overlays, mode, at..at + 1)
                .pop()
        });
        let leaf = |p: &Placed| (p.overlay, p.offset);
        let before = self.hex.hover.as_ref().map(|(_, _, p)| leaf(p));
        let after = placed.as_ref().map(leaf);
        self.hex.hover = placed.map(|p| (id, position, p));
        let byte = at.map(|at| (id, at));
        let moved = self.hex.hover_byte != byte;
        self.hex.hover_byte = byte;
        before != after || moved
    }

    /// Scrolls pane `id`'s hex view to its cursor as `how` says.
    fn reveal_hex(&mut self, id: PaneId, how: Reveal) {
        let Some(image) = self.hex_image() else {
            return;
        };
        let visible = self.rows(id, self.settings.listing_line_height);
        let Some(mode) = self.panes.get(&id).map(|s| s.hex.mode) else {
            return;
        };
        let rows = image.rows(mode);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let hex = &mut state.hex;
        let line = image.row_of(mode, hex.cursor);
        hex.scroll.smooth.stop();
        let anchor = &mut hex.scroll.anchor;
        match how {
            Reveal::Jump => anchor.focus(line, rows, visible),
            Reveal::Keys => anchor.reveal(line, rows, visible, visible / 6),
            Reveal::Pointer => anchor.reveal(line, rows, visible, 0),
        }
    }

    /// Pane `id`'s hex cursor moved: its listing cursor and the sync group
    /// follow the selection's first byte.
    fn hex_moved(&mut self, id: PaneId) {
        let address = self.hex_address(id);
        let bytes = self.hex_bytes(id);
        if let (Some(address), Some(listing)) = (address, self.listing.clone())
            && let Some(state) = self.panes.get_mut(&id)
        {
            state.listing.cursor = listing.line_of(address);
            state.listing.lit = None;
            // Its listing selects the lines of the bytes, as when back.
            select_lines(&mut state.listing, &listing, bytes);
            state.hex.followed = Some(state.listing.cursor);
        }
        self.moved(id);
    }

    /// Puts pane `id`'s hex cursor on position `at` (a find's match),
    /// revealed as a jump; the listing and the sync group follow.
    pub(crate) fn hex_land(&mut self, id: PaneId, at: u64) {
        if let Some(state) = self.panes.get_mut(&id) {
            state.hex.select(at, false);
        }
        self.reveal_hex(id, Reveal::Jump);
        self.hex_moved(id);
    }

    /// Copies pane `id`'s selected bytes as `format`.
    pub(crate) fn copy_hex(&self, id: PaneId, format: CopyFormat, cx: &mut Context<Self>) {
        let (Some(image), Some(session), Some((mode, _, selection))) = (
            self.hex_image(),
            self.session.as_ref(),
            self.pane_byte_range(id),
        ) else {
            return;
        };
        let Some((bytes, _)) = session.loaded() else {
            return;
        };
        let end = selection.end.min(selection.start + COPIED);
        let read = image.read(bytes, mode, selection.start..end);
        if !read.is_empty() {
            cx.write_to_clipboard(ClipboardItem::new_string(copy_text(&read, format)));
        }
    }

    // ---- the apply-type field ----

    /// `Alt+Q`: the field for a C type at pane `id`'s selected bytes (the
    /// user's type there to edit, if any).
    pub(crate) fn open_type_field(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(image) = self.hex_image() else {
            return;
        };
        let Some((mode, _, selection)) = self.pane_byte_range(id) else {
            return;
        };
        let start = selection.start;
        let anchor = match (mode, image.address_of(start, mode)) {
            (_, Some(address)) => Anchor::Address(address),
            (Mode::File, None) => Anchor::File(start),
            (Mode::Address, None) => return,
        };
        let current = self
            .hex
            .user
            .iter()
            .find(|o| o.anchor == anchor)
            .and_then(|o| o.text.clone())
            .unwrap_or_default();
        let input = cx.new(|cx| InputState::new(window, cx).default_value(current));
        let changes =
            cx.subscribe_in(
                &input,
                window,
                |this, input, e: &InputEvent, window, cx| match e {
                    InputEvent::Change => {
                        let text = input.read(cx).value().to_string();
                        let error = this.hex.types.as_ref().and_then(|types| {
                            if text.trim().is_empty() {
                                return None;
                            }
                            types.clone().apply(&text).err().map(|e| e.message)
                        });
                        if let Some(field) = &mut this.hex.field {
                            field.error = error;
                        }
                        cx.notify();
                    }
                    InputEvent::PressEnter { .. } => {
                        let text = input.read(cx).value().to_string();
                        this.commit_type_field(&text, window, cx);
                    }
                    InputEvent::Focus | InputEvent::Blur => {}
                },
            );
        let this = cx.weak_entity();
        let handle = window.window_handle();
        let escape = cx.intercept_keystrokes(move |event, window, cx| {
            if window.window_handle() != handle || event.keystroke.key != "escape" {
                return;
            }
            let closed = this
                .update(cx, |this, cx| {
                    let open = this.hex.field.is_some();
                    this.close_type_field(window, cx);
                    open
                })
                .unwrap_or(false);
            if closed {
                cx.stop_propagation();
            }
        });
        input.update(cx, |s, cx| {
            s.select_all(window, cx);
            s.focus(window, cx);
        });
        self.hex.field = Some(TypeField {
            pane: id,
            anchor,
            input,
            error: None,
            _subs: [changes, escape],
        });
        cx.notify();
    }

    /// Lays the type `text` names (or defines, as C) over the field's
    /// place, saved with the project; an empty text removes the user's
    /// type there.
    fn commit_type_field(&mut self, text: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(field) = &self.hex.field else {
            return;
        };
        let anchor = field.anchor;
        let pane = field.pane;
        let text = text.trim();
        if text.is_empty() {
            self.hex.user.retain(|o| o.anchor != anchor);
        } else {
            let Some(types) = &mut self.hex.types else {
                return;
            };
            match types.apply(text) {
                Ok(layout) => {
                    self.hex.user.retain(|o| o.anchor != anchor);
                    self.hex.user.push(user_overlay(anchor, layout, text));
                }
                Err(error) => {
                    if let Some(field) = &mut self.hex.field {
                        field.error = Some(error.message);
                    }
                    cx.notify();
                    return;
                }
            }
        }
        self.hex.dirty = true;
        self.save_user_overlays();
        self.hex.field = None;
        // An edit pins a preview tab.
        self.pin_active(pane);
        self.focus_pane(pane, window, cx);
    }

    /// Saves the user's overlays in the project.
    fn save_user_overlays(&mut self) {
        let Some(project) = self
            .session
            .as_ref()
            .and_then(binbun_gui_view::session::Session::project)
        else {
            return;
        };
        if let Err(error) = save_overlays(&project.overlays(), &self.hex.user) {
            self.error = Some(error);
        }
    }

    fn close_type_field(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(field) = self.hex.field.take() {
            self.focus_pane(field.pane, window, cx);
        }
    }

    // ---- the pane ----

    /// Pane `id`'s hex view: the bytes, and its side area right of them or
    /// under them ([`Self::side_place`]), in a split whose divider drags.
    pub fn render_hex(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let bytes = self.render_bytes(id, window, cx);
        let cw = self.char_width(window);
        let place = self.side_place(id, cw);
        let side = match place {
            SidePlace::Hidden => None,
            SidePlace::Beside | SidePlace::Under => self.render_side(id, place, cx),
        };
        let share = self
            .panes
            .get(&id)
            .map_or(0.5, |s| s.hex.side_split.share());
        let outer = Rc::clone(&self.hex.sides.entry(id).or_default().pane);
        let root = div().size_full().relative().flex().child(
            canvas(
                move |b, window, _| {
                    // Another width may move the side area: drawn
                    // again with it.
                    let width = outer.get().size.width;
                    outer.set(b);
                    if width != b.size.width {
                        window.request_animation_frame();
                    }
                },
                |_, (), _, _| {},
            )
            .absolute()
            .size_full(),
        );
        match side {
            Some(side) if place == SidePlace::Under => {
                // The divider's hit area, centred on the side area's top
                // hairline; a double-click halves the pane again.
                let handle = div()
                    .id(("hex-side-divider", id.0))
                    .absolute()
                    .left_0()
                    .right_0()
                    .top(px(-1.5))
                    .h(px(4.0))
                    .cursor_row_resize()
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            this.layout_ui.drag = Some(EdgeDrag::HexSide(id));
                            cx.stop_propagation();
                            cx.notify();
                        }),
                    )
                    .on_click(cx.listener(move |this, e: &ClickEvent, _, cx| {
                        if e.click_count() == 2
                            && let Some(state) = this.panes.get_mut(&id)
                        {
                            state.hex.side_split = SideSplit::default();
                            cx.notify();
                        }
                    }));
                root.flex_col()
                    .child(
                        div()
                            .flex_1()
                            .flex_grow(1.0 - share)
                            .min_h_0()
                            .w_full()
                            .child(bytes),
                    )
                    .child(
                        div()
                            .relative()
                            .flex_1()
                            .flex_grow(share)
                            .min_h_0()
                            .w_full()
                            .flex()
                            .child(side)
                            .child(handle),
                    )
                    .into_any_element()
            }
            side => root
                .child(div().flex_1().min_w_0().h_full().child(bytes))
                .children(side)
                .into_any_element(),
        }
    }

    /// Follows the divider between pane `id`'s bytes and its side area
    /// under them dragged to `y` (the window's): each kept
    /// [`SIDE_MIN`] high.
    pub fn drag_hex_side(&mut self, id: PaneId, y: Pixels) {
        let Some(bounds) = self.hex.sides.get(&id).map(|s| s.pane.get()) else {
            return;
        };
        let min = f32::from(self.z(SIDE_MIN));
        if let Some(state) = self.panes.get_mut(&id) {
            state.hex.side_split.drag(
                f32::from(y - bounds.origin.y),
                f32::from(bounds.size.height),
                min,
            );
        }
    }

    /// Where pane `id`'s side area goes: hidden by its toolbar's toggle,
    /// else beside the bytes (characters `cw` wide) if the pane, as last
    /// drawn, is wide enough for both, else under them.
    fn side_place(&self, id: PaneId, cw: f32) -> SidePlace {
        let (Some(image), Some(state)) = (self.hex_image(), self.panes.get(&id)) else {
            return SidePlace::Hidden;
        };
        let columns = Columns {
            prefix: image.prefix_width(state.hex.mode),
        };
        let bytes =
            2.0 * self.row(MARGIN) + f(columns.width() as u64) * cw + f32::from(self.z(SCROLLBAR));
        let width = self
            .hex
            .sides
            .get(&id)
            .map_or(0.0, |s| f32::from(s.pane.get().size.width));
        state
            .hex
            .side_place(width, bytes, f32::from(self.z(SIDE_WIDTH)))
    }

    /// Pane `id`'s bytes.
    #[expect(clippy::too_many_lines, reason = "one row's layers, in order")]
    fn render_bytes(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let cw = self.char_width(window);
        self.ensure_hex();
        let theme = self.theme;
        let focused = self.layout.focused() == id;
        let row_h = self.row(self.settings.listing_line_height);
        let visible = self.rows(id, self.settings.listing_line_height);
        // The pane's bottom corners it has: the side area takes the
        // right one beside it, both under it.
        let place = self.side_place(id, cw);
        let corner = self.island_corner();
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        let bounds = Rc::clone(&state.bounds);
        let mut pane = div()
            .id(("hex", id.0))
            .key_context("Code")
            .track_focus(&state.focus)
            .size_full()
            .relative()
            .overflow_hidden()
            .bg(hsla(theme.editor))
            .when(place != SidePlace::Under, |d| d.rounded_bl(corner))
            .when(place == SidePlace::Hidden, |d| d.rounded_br(corner))
            .font_family(self.settings.code_font.clone())
            .font_features(self.font_features())
            .text_size(px(self.code_size()))
            .line_height(px(row_h))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.hex_down(id, e, window, cx);
                }),
            )
            .on_mouse_move(cx.listener(move |this, e: &MouseMoveEvent, _, cx| {
                this.hex_drag(id, e, cx);
            }))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    this.sideways_drag = None;
                    if let Some(s) = this.panes.get_mut(&id) {
                        s.hex.dragging = false;
                        s.hex.overview_drag = false;
                    }
                    cx.notify();
                }),
            )
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                this.hex_wheel(id, e);
                cx.notify();
            }))
            .on_hover(cx.listener(move |this, hovered: &bool, _, cx| {
                if !*hovered {
                    let card = this.hex.hover.take().is_some();
                    let byte = this.hex.hover_byte.take().is_some();
                    if card || byte {
                        cx.notify();
                    }
                }
            }))
            .on_key_down(cx.listener(move |this, e: &KeyDownEvent, _, cx| {
                if this.hex_key(id, e) {
                    cx.stop_propagation();
                    cx.notify();
                }
            }))
            .child(measured(bounds).absolute().size_full());
        let Some(image) = self.hex_image() else {
            return pane.into_any_element();
        };
        let mode = state.hex.mode;
        let rows = image.rows(mode);
        self.hex_follow(id, &image, rows, visible, window);
        // The whole program's globals in view, laid out.
        let shown = self.panes.get(&id).and_then(|state| {
            let first = state.hex.scroll.anchor.line;
            let end = first.saturating_add(visible + 1).min(rows);
            let mode = state.hex.mode;
            let addresses =
                (first..end).filter_map(|n| image.address_of(image.row_start(mode, n)?, mode));
            Some(addresses.clone().min()?..addresses.max()? + ROW)
        });
        if let Some(shown) = shown {
            let wanted = self.hex.program.overlapping(shown);
            // The cursor's field now that its global has fields.
            if self.lay_out_globals(wanted) {
                self.tree_follow(id);
            }
        }
        let overview = self.hex_overview(&image, mode);
        // The rows scrolled sideways, the cursor's byte kept in view.
        let columns = Columns {
            prefix: image.prefix_width(mode),
        };
        let left = self.row(MARGIN);
        let x_of = |col: usize| left + f(col as u64) * cw;
        let cursor_band = self.panes.get(&id).and_then(|s| {
            let (cursor, text) = (s.hex.cursor, s.hex.text);
            let start = image.row_start(mode, image.row_of(mode, cursor))?;
            let i = cursor.saturating_sub(start);
            let x = x_of(if text {
                columns.text(i)
            } else {
                columns.hex(i)
            });
            Some(((cursor, u64::from(text)), (x - 4.0 * cw, x + 6.0 * cw)))
        });
        let sx = self.follow_sideways(id, 0.0, cursor_band);
        let Some(state) = self.panes.get(&id) else {
            return pane.into_any_element();
        };
        let hex = &state.hex;
        let (Some(session), listing) = (self.session.as_ref(), self.listing.clone()) else {
            return pane.into_any_element();
        };
        let Some((bytes, _)) = session.loaded() else {
            return pane.into_any_element();
        };
        let lines = listing.as_ref().map(|l| l.lines());
        let overlays = Arc::clone(&self.hex.overlays);
        let selection = hex.selection();
        let cursor = hex.cursor;
        let first = hex.scroll.anchor.line;
        let offset = hex.scroll.anchor.offset;
        let end = first.saturating_add(visible + 1).min(rows);
        let mut quads: Vec<Quad> = Vec::new();
        let hover_byte = self
            .hex
            .hover_byte
            .filter(|(pane, _)| *pane == id)
            .map(|(_, at)| at);
        // The leaf under the cursor, outlined wherever it shows.
        let current = image
            .placed(&overlays, mode, cursor..cursor + 1)
            .pop()
            .map(|p| (p.overlay, p.offset));
        for n in first..end {
            let y = f(n - first) * row_h - offset;
            let Some(start) = image.row_start(mode, n) else {
                continue;
            };
            let in_row = start..start + ROW;
            // The byte under the pointer, lit in the digits and the
            // characters alike.
            if let Some(at) = hover_byte.filter(|at| in_row.contains(at)) {
                let i = at - start;
                let hex = (x_of(columns.hex(i)) - 1.0, x_of(columns.hex(i) + 2) + 1.0);
                let text = (x_of(columns.text(i)), x_of(columns.text(i) + 1));
                for (x0, x1) in [hex, text] {
                    quads.push(Quad {
                        x: x0.round(),
                        y,
                        w: (x1 - x0).round(),
                        h: row_h,
                        color: with_alpha(theme.border_focused, 0x66),
                    });
                }
            }
            let cells = image.cells(bytes, lines, mode, in_row.clone());
            // Each byte's leaf (the last overlay's: the user's over the
            // debug information's over the headers').
            let mut leaves = [None::<(usize, u64, u64)>; 16];
            for p in image.placed(&overlays, mode, in_row.clone()) {
                for at in p.start..p.end {
                    if let Some(slot) = usize::try_from(at - start)
                        .ok()
                        .and_then(|i| leaves.get_mut(i))
                    {
                        *slot = Some((p.overlay, p.offset, p.ordinal));
                    }
                }
                if current == Some((p.overlay, p.offset)) {
                    let (a, b) = (p.start - start, p.end - start);
                    let hex = (
                        x_of(columns.hex(a)) - 1.0,
                        x_of(columns.hex(b - 1) + 2) + 1.0,
                    );
                    let text = (x_of(columns.text(a)), x_of(columns.text(b - 1) + 1));
                    let overlay = overlays.get(p.overlay);
                    let at = |offset: u64| overlay.and_then(|o| image.position(o, mode, offset));
                    let sides = (
                        at(p.offset) == Some(p.start),
                        at(p.offset + p.size - 1) == Some(p.end - 1),
                    );
                    for (x0, x1) in [hex, text] {
                        quads.extend(frame(
                            (x0.round(), y, (x1 - x0).round(), row_h),
                            sides,
                            theme.text_muted,
                        ));
                    }
                }
            }
            let cursor_row = in_row.contains(&cursor);
            let (text, runs) = self.hex_text(
                &image,
                (id, mode, start),
                &cells,
                &leaves,
                &selection,
                cursor,
                columns.prefix,
            );
            let background = cursor_row.then(|| {
                if focused {
                    theme.active_line
                } else {
                    theme.lit()
                }
            });
            // Item boundaries, hairlines between bytes.
            for (i, cell) in cells.iter().enumerate().skip(1) {
                if cell.start && cell.kind != Kind::Gap {
                    let x = x_of(columns.hex(i as u64)) - cw * 0.5;
                    quads.push(Quad {
                        x: x.round(),
                        y,
                        w: 1.0,
                        h: row_h,
                        color: with_alpha(theme.border, 0xc0),
                    });
                }
            }
            pane = pane.child(
                div()
                    .absolute()
                    .top(px(y))
                    .left_0()
                    .right(self.z(SCROLLBAR))
                    .h(px(row_h))
                    .overflow_hidden()
                    .when_some(background, |d, b| d.bg(hsla(b)))
                    .child(scrolled(
                        0.0,
                        sx,
                        div()
                            .pl(px(left))
                            .flex()
                            .whitespace_nowrap()
                            .child(StyledText::new(text).with_runs(runs)),
                    )),
            );
        }
        // The frames and hairlines move with the rows, clipped as they are.
        pane = pane.child(
            div()
                .absolute()
                .top_0()
                .bottom_0()
                .left_0()
                .right(self.z(SCROLLBAR))
                .overflow_hidden()
                .child(
                    canvas(
                        |_, _, _| {},
                        move |bounds, (), window, _| {
                            for q in &quads {
                                window.paint_quad(fill(
                                    Bounds::new(
                                        point(
                                            bounds.origin.x + px(q.x - sx),
                                            bounds.origin.y + px(q.y),
                                        ),
                                        size(px(q.w), px(q.h)),
                                    ),
                                    hsla(q.color),
                                ));
                            }
                        },
                    )
                    .absolute()
                    .size_full(),
                ),
        );
        let widest = 2.0 * left + f(columns.width() as u64) * cw;
        let sideways_bar = self.measured_sideways(id, 0.0, widest);
        let strip = overview.map(|o| {
            let bands = self.hex_bands(id, &o);
            self.hex_strip(id, &bands, rows)
        });
        // The others' ticks over the strip, where it is.
        let ticks = if strip.is_some() {
            let h = self
                .panes
                .get(&id)
                .map_or(0.0, |s| f32::from(s.bounds.get().size.height));
            let image = Arc::clone(&image);
            #[expect(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                reason = "a strip's pixels"
            )]
            let fraction = move |cursor: &Cursor| {
                let at = image.convert(cursor.address, Mode::Address, mode)?;
                Some((image.row_of(mode, at) as f64 / rows.max(1) as f64) as f32)
            };
            self.person_ticks(id, h, true, TickStyle::Bar, fraction, cx)
        } else {
            Vec::new()
        };
        let card = self.hex_card(id);
        pane.children(strip)
            .children(sideways_bar)
            .children(ticks)
            .children(card)
            .into_any_element()
    }

    /// Follows the shared cursor into pane `id` (a target set by another
    /// view, or its listing cursor moved) and eases a wheel's scrolling.
    fn hex_follow(
        &mut self,
        id: PaneId,
        image: &HexImage,
        rows: u64,
        visible: u64,
        window: &mut Window,
    ) {
        let duration = if self.settings.smooth_scroll {
            Duration::from_millis(u64::from(self.settings.smooth_scroll_ms))
        } else {
            Duration::ZERO
        };
        let row_h = self.row(self.settings.listing_line_height);
        let listing = self.listing.clone();
        let now = Instant::now();
        let dt = self
            .hex
            .frame_at
            .map_or(Duration::from_micros(16_667), |at| now - at);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let line_address = listing
            .as_ref()
            .and_then(|l| l.line(state.listing.cursor))
            .map(|l| l.address);
        let hex = &mut state.hex;
        let goto = match hex.target.take() {
            Some(target) => Some(target),
            None if hex.followed != Some(state.listing.cursor) => line_address.map(|a| (a, false)),
            None => None,
        };
        hex.followed = Some(state.listing.cursor);
        let mut reveal = None;
        if let Some((address, focus)) = goto
            && let Some(at) = image.convert(address, Mode::Address, hex.mode)
            && (focus || !hex.selection().contains(&at))
        {
            hex.select(at, false);
            reveal = Some(focus);
        }
        if hex.scroll.smooth.is_moving() {
            hex.scroll.frame(dt, duration, row_h, rows, visible);
            self.hex.frame_at = Some(now);
            window.request_animation_frame();
        } else {
            self.hex.frame_at = None;
        }
        if let Some(focus) = reveal {
            self.reveal_hex(id, if focus { Reveal::Jump } else { Reveal::Keys });
            self.tree_follow(id);
        }
    }

    /// Row `start`'s text: the prefix, the bytes, the characters, as runs
    /// (tints: each byte's overlay leaf's, else its kind's; the selection,
    /// muted zeros). `leaves` holds each byte's leaf: its overlay, offset
    /// and number.
    #[expect(clippy::too_many_arguments, reason = "one row's inputs")]
    fn hex_text(
        &self,
        image: &HexImage,
        (pane, mode, start): (PaneId, Mode, u64),
        cells: &[ByteCell],
        leaves: &[Option<(usize, u64, u64)>],
        selection: &Range<u64>,
        cursor: u64,
        prefix_width: usize,
    ) -> (String, Vec<TextRun>) {
        let theme = self.theme;
        let mut text = String::with_capacity(prefix_width + 70);
        let mut runs: Vec<TextRun> = Vec::with_capacity(70);
        let mut push = |text: &mut String, s: &str, color: u32, back: Option<u32>| {
            text.push_str(s);
            runs.push(self.text_run(s.len(), color, back));
        };
        let prefix = image.prefix(mode, start);
        let prefix_color = if (start..start + ROW).contains(&cursor) {
            theme.accent
        } else {
            theme.comment
        };
        let pad = prefix_width.saturating_sub(prefix.chars().count());
        push(&mut text, &prefix, prefix_color, None);
        push(
            &mut text,
            &" ".repeat(pad + 2),
            theme.editor_foreground,
            None,
        );
        let back = |i: usize| -> Option<u32> {
            let at = start + i as u64;
            let cell = cells.get(i)?;
            if at == cursor {
                Some(with_alpha(theme.accent, 0x80))
            } else if selection.contains(&at) {
                // Neutral, so it never reads as a kind's tint.
                Some(theme.element_selected)
            } else if let Some(found) = self.find_hex_mark(pane, at) {
                Some(found)
            } else if let Some((_, _, ordinal)) = leaves.get(i).copied().flatten() {
                Some(leaf_tint(theme, ordinal))
            } else {
                kind_color(theme, cell.kind).map(|c| with_alpha(c, TINT))
            }
        };
        let selected = |i: usize| selection.contains(&(start + i as u64));
        let color = |i: usize, cell: &ByteCell| match cell.value {
            Some(0) | None => theme.comment,
            Some(_) if selected(i) => theme.text,
            Some(_) => theme.editor_foreground,
        };
        for (i, cell) in cells.iter().enumerate() {
            let digits = match (cell.value, cell.kind) {
                (Some(v), _) => format!("{v:02X}"),
                (None, Kind::Gap) => "  ".to_owned(),
                (None, _) => "??".to_owned(),
            };
            push(&mut text, &digits, color(i, cell), back(i));
            if i + 1 < cells.len() {
                let sep = if i == 7 { "  " } else { " " };
                // The gap between two bytes takes their tint when both
                // have it: one leaf's, or one kind's with no item
                // starting at the second.
                let next = cells.get(i + 1);
                let leaf = |i: usize| leaves.get(i).copied().flatten();
                let same = match (leaf(i), leaf(i + 1)) {
                    (Some((o, a, _)), Some((p, b, _))) => o == p && a == b,
                    (None, None) => {
                        next.is_some_and(|n| !n.start) && next.is_some_and(|n| n.kind == cell.kind)
                    }
                    _ => false,
                };
                let joined = same
                    && back(i) == back(i + 1)
                    && start + i as u64 != cursor
                    && start + i as u64 + 1 != cursor;
                let both_selected = selection.contains(&(start + i as u64))
                    && selection.contains(&(start + i as u64 + 1));
                let gap = if both_selected {
                    Some(theme.element_selected)
                } else if joined {
                    back(i)
                } else {
                    None
                };
                push(&mut text, sep, theme.editor_foreground, gap);
            }
        }
        push(&mut text, "  ", theme.editor_foreground, None);
        for (i, cell) in cells.iter().enumerate() {
            let (ch, c) = match cell.value {
                Some(v @ 0x21..=0x7e) => (char::from(v), theme.editor_foreground),
                Some(0x20) => (' ', theme.editor_foreground),
                Some(_) => ('.', theme.comment),
                None if cell.kind == Kind::Gap => (' ', theme.comment),
                None => ('?', theme.comment),
            };
            let mut s = [0u8; 4];
            push(&mut text, ch.encode_utf8(&mut s), c, back(i));
        }
        (text, runs)
    }

    /// The overview strip's bands for pane `id`: each band of rows by its
    /// kind (or entropy), a run of one colour one quad; made again only
    /// when the overview, the strip's size or the theme change.
    fn hex_bands(&mut self, id: PaneId, overview: &Overview) -> Arc<Vec<Quad>> {
        let theme = self.theme;
        let Some(state) = self.panes.get(&id) else {
            return Arc::default();
        };
        let entropy = state.hex.entropy;
        let h = f32::from(state.bounds.get().size.height);
        let w = f32::from(self.z(SCROLLBAR)) - 1.0;
        let key = BandsKey {
            entropy,
            height: h,
            width: w,
            theme: std::ptr::from_ref(theme),
        };
        if let Some((of, made, bands)) = &self.hex.bands
            && Arc::ptr_eq(of, overview)
            && *made == key
        {
            return Arc::clone(bands);
        }
        let colors = overview.iter().map(|(kind, e)| {
            if entropy {
                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "0–255"
                )]
                let alpha = (e.clamp(0.0, 1.0) * 230.0) as u8;
                (alpha > 8).then(|| with_alpha(theme.number, alpha))
            } else {
                kind_color(theme, *kind).map(|c| with_alpha(c, BAND))
            }
        });
        let bands: Arc<Vec<Quad>> = Arc::new(
            runs(colors)
                .into_iter()
                .map(|(run, color)| {
                    let (y, extent) = band(&run, overview.len(), h);
                    Quad {
                        x: 1.0,
                        y,
                        w: w - 1.0,
                        h: extent,
                        color,
                    }
                })
                .collect(),
        );
        self.hex.bands = Some((Arc::clone(overview), key, Arc::clone(&bands)));
        bands
    }

    /// The overview strip in place of the scrollbar: its `bands`
    /// ([`Self::hex_bands`]), the viewport outlined, the cursor marked.
    fn hex_strip(&self, id: PaneId, bands: &Arc<Vec<Quad>>, data_rows: u64) -> AnyElement {
        let theme = self.theme;
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        let hex = &state.hex;
        let h = f32::from(state.bounds.get().size.height);
        let w = f32::from(self.z(SCROLLBAR)) - 1.0;
        let visible = self.rows(id, self.settings.listing_line_height);
        let data_row = |line: u64| line.min(data_rows);
        #[expect(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            reason = "a strip's pixels"
        )]
        let y_of = |row: u64| (row as f64 / data_rows.max(1) as f64) as f32 * h;
        let top = y_of(data_row(hex.scroll.anchor.line));
        let bottom = y_of(data_row(hex.scroll.anchor.line + visible)).max(top + 3.0);
        let image = self.hex_image();
        let cursor_row = image
            .as_ref()
            .map_or(0, |image| image.row_of(hex.mode, hex.cursor));
        let bands = Arc::clone(bands);
        let mut quads: Vec<Quad> = Vec::with_capacity(5);
        let line = theme.text_muted;
        for q in [
            (0.0, top, w, 1.0),
            (0.0, bottom - 1.0, w, 1.0),
            (0.0, top, 1.0, bottom - top),
            (w - 1.0, top, 1.0, bottom - top),
        ] {
            quads.push(Quad {
                x: q.0,
                y: q.1,
                w: q.2,
                h: q.3,
                color: line,
            });
        }
        quads.push(Quad {
            x: 0.0,
            y: y_of(cursor_row),
            w,
            h: 2.0,
            color: theme.accent,
        });
        div()
            .id(("hex-strip", id.0))
            .absolute()
            .top_0()
            .bottom_0()
            .right_0()
            .w(self.z(SCROLLBAR))
            .bg(hsla(theme.under(theme.panel)))
            .border_l_1()
            .border_color(hsla(theme.scrollbar_track_border))
            .child(
                canvas(
                    |_, _, _| {},
                    move |bounds, (), window, _| {
                        for q in bands.iter().chain(&quads) {
                            window.paint_quad(fill(
                                Bounds::new(
                                    point(bounds.origin.x + px(q.x), bounds.origin.y + px(q.y)),
                                    size(px(q.w), px(q.h)),
                                ),
                                hsla(q.color),
                            ));
                        }
                    },
                )
                .absolute()
                .size_full(),
            )
            .into_any_element()
    }

    /// The apply-type field, under its pane's cursor row (the hex view's,
    /// the unified listing's): an overlay of the window, outside the
    /// pane's key context (so its keys are text, never the pane's
    /// commands).
    pub fn render_type_field(&mut self) -> Option<AnyElement> {
        let theme = self.theme;
        let id = self.hex.field.as_ref()?.pane;
        let (left, top) = if self.shows_hex(id) {
            self.hex_field_place(id)?
        } else if self.shows_unified(id) {
            let (at, row_h) = self.unified_type_at(id)?;
            (at.x, at.y + px(row_h + 2.0))
        } else {
            self.hex.field = None;
            return None;
        };
        let field = self.hex.field.as_ref()?;
        Some(
            div()
                .absolute()
                .top(top)
                .left(left)
                .w(self.z(460.0))
                .flex()
                .flex_col()
                .font_family(self.settings.code_font.clone())
                .text_size(px(self.code_size()))
                .bg(hsla(solid(theme.panel)))
                .border_1()
                .border_color(hsla(if field.error.is_some() {
                    theme.error
                } else {
                    theme.border_focused
                }))
                .rounded(self.z(4.0))
                .shadow_lg()
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                .child(
                    div()
                        .px(self.z(6.0))
                        .text_color(hsla(theme.text))
                        .child(FieldInput::new(&field.input)),
                )
                .when_some(field.error.clone(), |d, error| {
                    d.child(
                        div()
                            .px(self.z(6.0))
                            .pb(self.z(2.0))
                            .text_size(px(self.code_size() * 0.9))
                            .text_color(hsla(theme.error))
                            .child(error),
                    )
                })
                .into_any_element(),
        )
    }

    /// Where the apply-type field goes in hex pane `id`, in the window:
    /// under the cursor's row, at its byte.
    fn hex_field_place(&self, id: PaneId) -> Option<(Pixels, Pixels)> {
        let image = self.hex_image()?;
        let state = self.panes.get(&id)?;
        let hex = &state.hex;
        let mode = hex.mode;
        let origin = state.bounds.get().origin;
        let row_h = self.row(self.settings.listing_line_height);
        let cw = self.char_width.unwrap_or(8.0);
        let columns = Columns {
            prefix: image.prefix_width(mode),
        };
        let row = image.row_of(hex.mode, hex.cursor);
        let first = hex.scroll.anchor.line;
        let y = if row >= first {
            f(row - first + 1) * row_h - hex.scroll.anchor.offset
        } else {
            0.0
        };
        let start = image.row_start(hex.mode, row).unwrap_or(hex.cursor);
        let x = self.row(MARGIN) + f(columns.hex(hex.cursor.saturating_sub(start)) as u64) * cw
            - hex.side.x;
        Some((origin.x + px(x), origin.y + px(y + 2.0)))
    }

    /// What is under `position` in pane `id`: the strip (and where on it,
    /// 0–1), else the line and column.
    fn hex_hit(&self, id: PaneId, position: Point<Pixels>) -> Option<HexHit> {
        let state = self.panes.get(&id)?;
        let b = state.bounds.get();
        let x = f32::from(position.x - b.origin.x);
        let y = f32::from(position.y - b.origin.y);
        let height = f32::from(b.size.height).max(1.0);
        if x > f32::from(b.size.width) - f32::from(self.z(SCROLLBAR)) {
            return Some(HexHit::Strip((y / height).clamp(0.0, 1.0)));
        }
        let row = self.row(self.settings.listing_line_height);
        let anchor = state.hex.scroll.anchor;
        let line = anchor.line + rows_in(y + anchor.offset + 1.0, row) - 1;
        let col = column(
            x - self.row(MARGIN) + state.hex.side.x,
            self.char_width.unwrap_or(8.0),
        );
        Some(HexHit::Bytes { line, col })
    }

    /// The position at line `line`, column `col` of pane `id`, and whether
    /// in the characters.
    fn hex_position(&self, id: PaneId, line: u64, col: usize) -> Option<(u64, bool)> {
        let image = self.hex_image()?;
        let mode = self.panes.get(&id)?.hex.mode;
        let row = line.min(image.rows(mode).checked_sub(1)?);
        let start = image.row_start(mode, row)?;
        let columns = Columns {
            prefix: image.prefix_width(mode),
        };
        let (i, text) = columns.byte_at(col).unwrap_or((0, false));
        Some((start + i, text))
    }

    /// Scrolls pane `id` so the strip's `fraction` is in the middle.
    fn hex_strip_to(&mut self, id: PaneId, fraction: f32) {
        let Some(image) = self.hex_image() else {
            return;
        };
        let visible = self.rows(id, self.settings.listing_line_height);
        let Some(mode) = self.panes.get(&id).map(|s| s.hex.mode) else {
            return;
        };
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            clippy::cast_sign_loss,
            reason = "a strip's pixel resolution"
        )]
        let row = (f64::from(fraction) * image.rows(mode) as f64) as u64;
        let line = row.saturating_sub(visible / 2);
        if let Some(state) = self.panes.get_mut(&id) {
            let anchor = &mut state.hex.scroll.anchor;
            state.hex.scroll.smooth.stop();
            anchor.line = line.min(ScrollAnchor::max_line(image.rows(mode), visible));
            anchor.offset = 0.0;
        }
    }

    fn hex_down(
        &mut self,
        id: PaneId,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.close_peek();
        self.hex.hover = None;
        if self.hex.field.is_some() {
            self.hex.field = None;
        }
        if self.layout.focused() != id {
            self.focus_pane(id, window, cx);
        }
        if self.sideways_down(id, e) {
            cx.notify();
            return;
        }
        match self.hex_hit(id, e.position) {
            Some(HexHit::Strip(fraction)) => {
                if let Some(state) = self.panes.get_mut(&id) {
                    state.hex.overview_drag = true;
                }
                self.hex_strip_to(id, fraction);
            }
            Some(HexHit::Bytes { line, col }) => {
                let Some((at, text)) = self.hex_position(id, line, col) else {
                    return;
                };
                if let Some(state) = self.panes.get_mut(&id) {
                    state.hex.dragging = true;
                    state.hex.text = text;
                }
                self.hex_select(id, at, e.modifiers.shift, Reveal::Pointer);
            }
            None => {}
        }
        cx.notify();
    }

    fn hex_drag(&mut self, id: PaneId, e: &MouseMoveEvent, cx: &mut Context<Self>) {
        if self.sideways_move(id, e) {
            cx.notify();
            return;
        }
        let Some(state) = self.panes.get(&id) else {
            return;
        };
        if !e.dragging() || !(state.hex.dragging || state.hex.overview_drag) {
            if !e.dragging() && self.hex_hover(id, e.position) {
                cx.notify();
            }
            return;
        }
        let strip = state.hex.overview_drag;
        match self.hex_hit(id, e.position) {
            Some(HexHit::Strip(fraction)) if strip => self.hex_strip_to(id, fraction),
            Some(HexHit::Bytes { .. }) if strip => {}
            Some(HexHit::Bytes { line, col }) => {
                if let Some((at, _)) = self.hex_position(id, line, col)
                    && self.panes.get(&id).is_some_and(|s| s.hex.cursor != at)
                {
                    self.hex_select(id, at, true, Reveal::Pointer);
                }
            }
            Some(HexHit::Strip(_)) | None => {}
        }
        cx.notify();
    }

    fn hex_wheel(&mut self, id: PaneId, e: &ScrollEvent) {
        let Some(image) = self.hex_image() else {
            return;
        };
        let row = self.row(self.settings.listing_line_height);
        let visible = self.rows(id, self.settings.listing_line_height);
        self.wheel_sideways(id, e, row);
        if e.modifiers.shift {
            return;
        }
        let Some(mode) = self.panes.get(&id).map(|s| s.hex.mode) else {
            return;
        };
        let total = image.rows(mode);
        if let Some(state) = self.panes.get_mut(&id) {
            state.hex.scroll.wheel(wheel(e), row, total, visible);
        }
    }

    /// The keys no command takes: left and right, Shift with the arrows,
    /// Home and End; whether it took `e`.
    fn hex_key(&mut self, id: PaneId, e: &KeyDownEvent) -> bool {
        let Some(image) = self.hex_image() else {
            return false;
        };
        let k = &e.keystroke;
        if k.modifiers.control || k.modifiers.alt || k.modifiers.platform {
            return false;
        }
        let Some(hex) = self.panes.get(&id).map(|s| &s.hex) else {
            return false;
        };
        let (mode, cursor) = (hex.mode, hex.cursor);
        let start = image
            .row_start(mode, image.row_of(mode, cursor))
            .unwrap_or(cursor);
        let to = match k.key.as_str() {
            "left" => image.step(mode, cursor, -1),
            "right" => image.step(mode, cursor, 1),
            "up" => image.step(mode, cursor, -16),
            "down" => image.step(mode, cursor, 16),
            "home" => start,
            "end" => start + ROW - 1,
            _ => return false,
        };
        self.hex_select(id, to, k.modifiers.shift, Reveal::Keys);
        true
    }

    /// The hex view's tools in pane `id`'s toolbar: addresses or file
    /// offsets, the overview by kinds or entropy.
    pub fn hex_tools(&self, id: PaneId, cx: &mut Context<Self>) -> Option<AnyElement> {
        if !self.shows_hex(id) {
            return None;
        }
        let theme = self.theme;
        let hex = &self.panes.get(&id)?.hex;
        let mode = hex.mode;
        let choice = |name: IconName, to: Mode, label: &'static str, cx: &mut Context<Self>| {
            let on = mode == to;
            div()
                .id(label)
                .flex()
                .items_center()
                .justify_center()
                .size(self.z(ICON_BUTTON))
                .rounded(self.z(3.0))
                .when(on, |d| d.bg(hsla(theme.element_selected)))
                .when(!on, |d| d.hover(|s| s.bg(hsla(theme.element_hover))))
                .tooltip(self.key_tooltip(label, Command::HexFileOffsets))
                .on_click(cx.listener(move |this, _, window, cx| {
                    if this.panes.get(&id).is_some_and(|s| s.hex.mode != to) {
                        this.layout.focus(id);
                        this.run(Command::HexFileOffsets, window, cx);
                    }
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
                .gap(self.z(6.0))
                .child(
                    self.icon_button(
                        ("hex-entropy", id.0),
                        IconName::Activity,
                        Command::HexEntropy,
                        true,
                        hex.entropy,
                        cx,
                    )
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, _| {
                            this.layout.focus(id);
                        }),
                    ),
                )
                .child(
                    div()
                        .flex()
                        .p(px(1.0))
                        .gap(px(1.0))
                        .rounded(self.z(4.0))
                        .border_1()
                        .border_color(hsla(theme.border_variant))
                        .child(choice(IconName::MapPin, Mode::Address, "Addresses", cx))
                        .child(choice(IconName::FileDigit, Mode::File, "File Offsets", cx)),
                )
                .child(
                    self.icon_button(
                        ("hex-side", id.0),
                        IconName::PanelRight,
                        Command::HexSide,
                        true,
                        !hex.side_hidden,
                        cx,
                    )
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, _| {
                            this.layout.focus(id);
                        }),
                    ),
                )
                .into_any_element(),
        )
    }

    // ---- the side area ----

    /// Pane `id`'s side area at `place`: the selection's place, the
    /// structure tree, the data inspector (the selection read as every
    /// type).
    #[expect(clippy::too_many_lines, reason = "the inspector's rows")]
    fn render_side(
        &mut self,
        id: PaneId,
        place: SidePlace,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        let theme = self.theme;
        let image = self.hex_image()?;
        let tree = self.render_tree(id, &image, cx);
        let hex = &self.panes.get(&id)?.hex;
        let (bytes, _) = self.session.as_ref()?.loaded()?;
        let selection = hex.selection();
        let read = image.read(
            bytes,
            hex.mode,
            selection.start..selection.start + INSPECTED,
        );
        let listing = self.listing.clone();
        let session = self.session.as_ref();
        let name = |address: u64| -> Option<String> {
            if !image.holds(Mode::Address, address) {
                return None;
            }
            let listing = listing.as_ref()?;
            Some(
                listing
                    .shown_name(address, session?.overlay())
                    .map_or_else(|| listing.describe(address), str::to_owned),
            )
        };
        let rows = inspect::inspect(&read, image.little(), image.model().pointer, &name);
        let code = self.settings.code_font.clone();
        let label_w = self.z(76.0);
        let cell = |text: String, color: u32| {
            div()
                .flex_1()
                .min_w_0()
                .overflow_hidden()
                .text_ellipsis()
                .whitespace_nowrap()
                .text_color(hsla(color))
                .child(text)
        };
        let line = |label: String| {
            div()
                .flex()
                .items_center()
                .gap(self.z(8.0))
                .h(self.z(20.0))
                .px(self.z(8.0))
                .child(
                    div()
                        .w(label_w)
                        .flex_none()
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .text_color(hsla(theme.text_muted))
                        .child(label),
                )
        };
        let mut table = div()
            .flex()
            .flex_col()
            .py(self.z(4.0))
            .font_family(code.clone())
            .child(
                line(String::new())
                    .child(cell("LE".to_owned(), theme.text_placeholder))
                    .child(cell("BE".to_owned(), theme.text_placeholder)),
            );
        for (k, row) in rows.into_iter().enumerate() {
            let mut l = line(row.label.to_owned());
            l = match row.values {
                Values::Two { little, big } => l
                    .child(cell(little, theme.text))
                    .child(cell(big, theme.text)),
                Values::One(text) => l.child(cell(text, theme.text)),
            };
            let target = row.target.filter(|&t| image.holds(Mode::Address, t));
            table = table.child(
                div()
                    .id(("inspector-row", k))
                    .hover(|s| s.bg(hsla(theme.element_hover)))
                    .when_some(target, |d, target| {
                        d.on_click(cx.listener(move |this, _, _, cx| this.jump(target, cx)))
                    })
                    .child(l),
            );
        }
        let header = div()
            .flex()
            .flex_none()
            .items_center()
            .h(self.bar(TOOLBAR_PAD))
            .px(self.z(8.0))
            .border_b_1()
            .border_color(hsla(theme.border_variant))
            .font_family(code)
            .whitespace_nowrap()
            .child(format!(
                "{}{} · {} {}",
                image
                    .address_of(selection.start, hex.mode)
                    .and_then(|a| image.section(a))
                    .map(|s| format!("{s}:"))
                    .unwrap_or_default(),
                image.prefix(hex.mode, selection.start),
                selection.end - selection.start,
                if selection.end - selection.start == 1 {
                    "byte"
                } else {
                    "bytes"
                }
            ));
        // Its most rows (the header and 19 readings): beside the bytes the
        // tree above it keeps its height; under them, in a lower area, the
        // two share it.
        let inspector = self.z(20.0 * 20.0 + 8.0);
        let area = div().id(("hex-side", id.0));
        let (area, table) = match place {
            SidePlace::Under => (
                area.size_full()
                    .border_t_1()
                    .rounded_b(self.island_corner()),
                table.flex_1().min_h_0().max_h(inspector),
            ),
            SidePlace::Beside | SidePlace::Hidden => (
                area.w(self.z(SIDE_WIDTH))
                    .flex_none()
                    .h_full()
                    .border_l_1()
                    .rounded_br(self.island_corner()),
                table.flex_none().h(inspector),
            ),
        };
        Some(
            area.overflow_hidden()
                .flex()
                .flex_col()
                .bg(hsla(theme.panel))
                .border_color(hsla(theme.border))
                .font_family(self.settings.ui_font.clone())
                .text_size(self.z(self.settings.ui_font_size))
                .line_height(self.z(self.ui_line()))
                .child(header)
                .child(tree)
                .child(
                    table
                        .overflow_hidden()
                        .border_t_1()
                        .border_color(hsla(theme.border_variant)),
                )
                .into_any_element(),
        )
    }

    /// The structure tree: every overlay a root, its rows in the table's
    /// columns (name, type, offset, size, the references into a whole
    /// program global's row, value), the lines in view only (the whole
    /// program's globals among them laid out).
    #[expect(clippy::too_many_lines, reason = "the header and each row's cells")]
    fn render_tree(&mut self, id: PaneId, image: &HexImage, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let drawn = self.hex.sides.entry(id).or_default();
        let focus = drawn.focus.get_or_insert_with(|| cx.focus_handle()).clone();
        let height = f32::from(drawn.bounds.get().size.height);
        let reveal = std::mem::take(&mut drawn.reveal);
        let bounds = Rc::clone(&drawn.bounds);
        let row_h = self.z(20.0);
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "rows in view"
        )]
        let visible = (height / f32::from(row_h)).floor().max(0.0) as usize;
        let count = if visible == 0 { 60 } else { visible + 1 };
        let mut lines = self.tree_lines(id);
        // The whole program's globals whose rows are in view, laid out.
        let top = self.panes.get(&id).map_or(0, |s| s.hex.tree_top);
        let shown = lines
            .get(top.min(lines.len())..(top + count).min(lines.len()))
            .unwrap_or_default();
        let first = image.headers().len();
        let wanted = hex_globals::roots_in(shown, first, &self.hex.program);
        if wanted.iter().any(|&i| !self.hex.program.is_laid(i)) {
            self.lay_out_globals(wanted);
            lines = self.tree_lines(id);
        }
        let overlays = Arc::clone(&self.hex.overlays);
        let Some(tree) = self.panes.get_mut(&id).map(|s| &mut s.hex) else {
            return div().into_any_element();
        };
        let mut top = tree.tree_top;
        if reveal && visible > 0 {
            let selected = tree.tree.selected.as_ref();
            if let Some(i) = lines.iter().position(|l| Some(&l.key) == selected) {
                if i < top {
                    top = i;
                } else if i >= top + visible {
                    top = i + 1 - visible;
                }
            }
        } else if reveal {
            // Not drawn yet: revealed once it is.
            if let Some(drawn) = self.hex.sides.get_mut(&id) {
                drawn.reveal = true;
            }
        }
        top = top.min(lines.len().saturating_sub(visible.max(1)));
        tree.tree_top = top;
        let selected_key = tree.tree.selected.clone();
        let file = self
            .session
            .as_ref()
            .and_then(|s| s.loaded())
            .map(|(b, _)| b);
        let read = |overlay: &Overlay, range: Range<u64>| -> Vec<u8> {
            let Some(file) = file else {
                return Vec::new();
            };
            let (space, base) = overlay.anchor.place();
            image.read(file, space, base + range.start..base + range.end)
        };
        let listing = self.listing.clone();
        let session = self.session.as_ref();
        let references = session
            .and_then(|s| s.database())
            .filter(|_| self.stage >= Stage::Referenced)
            .map(Database::references);
        let within = |bytes: Range<u64>| references.map_or(0, |r| r.within(bytes).len());
        let name = |address: u64| {
            listing
                .as_ref()?
                .shown_name(address, session?.overlay())
                .map(str::to_owned)
        };
        let cell = |text: String, width: Option<f32>, color: u32| {
            div()
                .when_some(width, |d, w| d.w(self.z(w)).flex_none())
                .when(width.is_none(), Styled::flex_1)
                .min_w_0()
                .overflow_hidden()
                .text_ellipsis()
                .text_color(hsla(color))
                .child(text)
        };
        let columns = |name: AnyElement, refs: AnyElement, cells: [(String, u32); 4]| {
            let [ty, offset, size, value] = cells;
            div()
                .flex()
                .items_center()
                .gap(self.z(6.0))
                .h(row_h)
                .px(self.z(6.0))
                .whitespace_nowrap()
                .child(div().w(self.z(150.0)).flex_none().min_w_0().child(name))
                .child(cell(ty.0, Some(110.0), ty.1))
                .child(cell(offset.0, Some(56.0), offset.1))
                .child(cell(size.0, Some(40.0), size.1))
                .child(refs)
                .child(cell(value.0, None, value.1))
        };
        let refs_cell = |n: Option<usize>| {
            div()
                .w(self.z(REFS_WIDTH))
                .flex_none()
                .flex()
                .justify_end()
                .text_color(hsla(theme.text_muted))
                .children(n.map(|n| n.to_string()))
        };
        let header = columns(
            cell("Name".to_owned(), None, theme.text_placeholder).into_any_element(),
            refs_cell(None)
                .text_color(hsla(theme.text_placeholder))
                .child("Xrefs")
                .into_any_element(),
            ["Type", "Offset", "Size", "Value"].map(|t| (t.to_owned(), theme.text_placeholder)),
        )
        .border_b_1()
        .border_color(hsla(theme.border_variant));
        let mut list = div()
            .absolute()
            .top_0()
            .left_0()
            .right_0()
            .flex()
            .flex_col();
        for (n, line) in lines.iter().enumerate().skip(top).take(count) {
            let Some(row) = hex_tree::row(&overlays, &line.key, &read, image.little(), &name)
            else {
                continue;
            };
            let selected = selected_key.as_ref() == Some(&line.key);
            let offset = match (line.key.steps.is_empty(), row.bits) {
                (true, _) => match overlays.get(line.key.root).map(|o| o.anchor) {
                    Some(Anchor::File(at) | Anchor::Address(at)) => format!("{at:X}"),
                    None => String::new(),
                },
                (false, Some((bit, _))) => format!("+{:X}.{}", row.offset + bit / 8, bit % 8),
                (false, None) => format!("+{:X}", row.offset),
            };
            // A file's headers and tables are far apart: no one size.
            let sparse = line.key.steps.is_empty()
                && overlays.get(line.key.root).is_some_and(|o| o.layout.sparse);
            let size = match row.bits {
                Some((_, width)) => format!(":{width}"),
                None if sparse => String::new(),
                None => row.size.to_string(),
            };
            let key = line.key.clone();
            let toggled = line.key.clone();
            let chevron = div()
                .id(("tree-chevron", n))
                .w(self.z(14.0))
                .flex_none()
                .flex()
                .items_center()
                .when(line.expandable, |d| {
                    d.child(icon(
                        if line.expanded {
                            IconName::ChevronDown
                        } else {
                            IconName::ChevronRight
                        },
                        self.z(12.0),
                        hsla(theme.text_muted),
                    ))
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            this.tree_toggle(id, &toggled);
                            cx.stop_propagation();
                            cx.notify();
                        }),
                    )
                });
            let depth = f32::from(u16::try_from(line.depth).unwrap_or(u16::MAX));
            let name_cell = div()
                .flex()
                .items_center()
                .child(div().w(self.z(12.0 * depth)).flex_none())
                .child(chevron)
                .child(cell(row.name, None, theme.text))
                .into_any_element();
            let value_color = if row.value.starts_with('"') {
                theme.string
            } else {
                theme.text
            };
            // The references into a whole program global's row: a double
            // click lists them.
            let bytes = hex_globals::row_bytes(&overlays, &line.key);
            let refs = bytes.clone().map(within).filter(|&n| n > 0);
            let refs = refs_cell(refs)
                .id(("tree-refs", n))
                .when_some(bytes.filter(|_| refs.is_some()), |d, bytes| {
                    d.on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                            if e.click_count == 2 {
                                this.open_xrefs_to(
                                    id,
                                    bytes.start,
                                    bytes.end - bytes.start,
                                    window,
                                    cx,
                                );
                                cx.stop_propagation();
                                cx.notify();
                            }
                        }),
                    )
                })
                .into_any_element();
            list = list.child(
                columns(
                    name_cell,
                    refs,
                    [
                        (row.ty, theme.type_),
                        (offset, theme.text_muted),
                        (size, theme.text_muted),
                        (row.value, value_color),
                    ],
                )
                .id(("tree-row", n))
                .when(selected, |d| d.bg(hsla(theme.element_selected)))
                .when(!selected, |d| d.hover(|s| s.bg(hsla(theme.element_hover))))
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                        if e.click_count == 2 {
                            this.tree_toggle(id, &key);
                        }
                        this.tree_select(id, &key);
                        if let Some(focus) = this.hex.sides.get(&id).and_then(|s| s.focus.as_ref())
                        {
                            window.focus(focus, cx);
                        }
                        cx.notify();
                    }),
                ),
            );
        }
        div()
            .id(("struct-tree", id.0))
            .track_focus(&focus)
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .font_family(self.settings.code_font.clone())
            .on_key_down(cx.listener(move |this, e: &KeyDownEvent, window, cx| {
                if this.tree_key(id, e, window, cx) {
                    cx.stop_propagation();
                    cx.notify();
                }
            }))
            .child(header)
            .child(
                div()
                    .id(("struct-tree-rows", id.0))
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .overflow_hidden()
                    .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                        this.tree_wheel(id, e);
                        cx.notify();
                    }))
                    .child(measured(bounds).absolute().size_full())
                    .child(list),
            )
            .into_any_element()
    }

    /// Pane `id`'s structure tree's lines as shown (made again once it or
    /// the overlays changed).
    fn tree_lines(&mut self, id: PaneId) -> Arc<Vec<TreeLine>> {
        let Some(state) = self.panes.get(&id) else {
            return Arc::default();
        };
        let overlays = &self.hex.overlays;
        let side = self.hex.sides.entry(id).or_default();
        Arc::clone(
            side.lines
                .get_or_insert_with(|| Arc::new(state.hex.tree.lines(overlays))),
        )
    }

    /// Shows or hides the children of row `key` of pane `id`'s tree.
    fn tree_toggle(&mut self, id: PaneId, key: &Key) {
        if let Some(state) = self.panes.get_mut(&id) {
            state.hex.tree.toggle(key);
        }
        if let Some(side) = self.hex.sides.get_mut(&id) {
            side.lines = None;
        }
    }

    /// Set type and the references on the selected row of pane `id`'s
    /// tree while it has the focus: whether `command` was taken, if it is
    /// one of them there.
    fn tree_command(
        &mut self,
        id: PaneId,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Option<bool> {
        if !matches!(command, Command::SetType | Command::Xrefs) {
            return None;
        }
        let focus = self.hex.sides.get(&id)?.focus.as_ref()?;
        if !focus.is_focused(window) {
            return None;
        }
        let key = self.panes.get(&id)?.hex.tree.selected.clone()?;
        Some(if command == Command::SetType {
            self.open_global_type(id, &key, window, cx)
        } else {
            self.tree_xrefs(id, &key, window, cx)
        })
    }

    /// Lists in pane `id` the references into the bytes of row `key` of a
    /// whole program global; whether it is one that has references.
    fn tree_xrefs(
        &mut self,
        id: PaneId,
        key: &Key,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(bytes) = hex_globals::row_bytes(&self.hex.overlays, key) else {
            return false;
        };
        let referred = self
            .session
            .as_ref()
            .and_then(|s| s.database())
            .filter(|_| self.stage >= Stage::Referenced)
            .is_some_and(|db| !db.references().within(bytes.clone()).is_empty());
        if referred {
            self.open_xrefs_to(id, bytes.start, bytes.end - bytes.start, window, cx);
        }
        referred
    }

    /// `Y` on the root row `key` of a whole program global in pane `id`'s
    /// tree: Set type for the global, over the row's type; whether it is
    /// one.
    fn open_global_type(
        &mut self,
        id: PaneId,
        key: &Key,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        if !key.steps.is_empty() {
            return false;
        }
        let start = match self.hex.overlays.get(key.root) {
            Some(Overlay {
                anchor: Anchor::Address(start),
                source: Source::Program,
                ..
            }) => *start,
            _ => return false,
        };
        let Some(field) = self
            .session
            .as_ref()
            .and_then(|s| s.global_type(start))
            .and_then(|typed| SetTypeField::global(&typed))
        else {
            return false;
        };
        self.open_type_input(id, field, Place::Tree, window, cx);
        true
    }

    /// Where the Set type field over the selected row's type in pane
    /// `id`'s tree shows, in the window, and the row's height; `None` with
    /// the row out of sight.
    pub fn hex_type_at(&mut self, id: PaneId) -> Option<(Point<Pixels>, f32)> {
        let lines = self.tree_lines(id);
        let hex = &self.panes.get(&id)?.hex;
        let selected = hex.tree.selected.as_ref()?;
        let i = lines.iter().position(|l| &l.key == selected)?;
        let row_h = f32::from(self.z(20.0));
        let bounds = self.hex.sides.get(&id)?.bounds.get();
        let n = i.checked_sub(hex.tree_top)?;
        let y = f(n as u64) * row_h;
        if y + row_h > f32::from(bounds.size.height) {
            return None;
        }
        // The type column: after the row's padding, the name and a gap.
        let x = self.z(6.0 + 150.0 + 6.0);
        Some((bounds.origin + point(x, px(y)), row_h))
    }

    /// The focus on pane `id`'s structure tree.
    pub fn focus_hex_tree(&mut self, id: PaneId, window: &mut Window, cx: &mut Context<Self>) {
        match self.hex.sides.get(&id).and_then(|s| s.focus.as_ref()) {
            Some(focus) => window.focus(focus, cx),
            None => self.focus_pane(id, window, cx),
        }
    }

    /// The wheel over pane `id`'s structure tree: its lines scroll.
    fn tree_wheel(&mut self, id: PaneId, e: &ScrollEvent) {
        let row = f32::from(self.z(20.0));
        let lines = match wheel(e) {
            Wheel::Lines(lines) => -lines * 3.0,
            Wheel::Pixels(pixels) => -pixels / row,
        };
        #[expect(clippy::cast_possible_truncation, reason = "a wheel's lines")]
        let delta = lines.round() as i64;
        let len = self.tree_lines(id).len();
        if let Some(state) = self.panes.get_mut(&id) {
            let top = state
                .hex
                .tree_top
                .saturating_add_signed(isize::try_from(delta).unwrap_or(0));
            state.hex.tree_top = top.min(len.saturating_sub(1));
        }
    }

    /// The structure tree's keys (a file tree's): Up and Down
    /// move, Left collapses (else goes to the parent), Right expands (else
    /// goes to the first child), Enter toggles (a field without children
    /// lists the references into it, as `X` does on any row of a whole
    /// program global), `Y` sets a whole program global's type on its
    /// root; the selected row's bytes are selected in pane `id`. Whether
    /// it took `e`.
    fn tree_key(
        &mut self,
        id: PaneId,
        e: &KeyDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let k = &e.keystroke;
        if k.modifiers.control || k.modifiers.alt || k.modifiers.platform || k.modifiers.shift {
            return false;
        }
        let lines = self.tree_lines(id);
        let selected = self
            .panes
            .get(&id)
            .and_then(|s| s.hex.tree.selected.clone());
        let to = match k.key.as_str() {
            "up" => Move::Up,
            "down" => Move::Down,
            "left" => Move::Left,
            "right" => Move::Right,
            "enter" => {
                let Some(key) = selected else {
                    return true;
                };
                let leaf = lines.iter().any(|l| l.key == key && !l.expandable);
                if !(leaf && self.tree_xrefs(id, &key, window, cx)) {
                    self.tree_toggle(id, &key);
                }
                return true;
            }
            "x" => {
                return selected.is_some_and(|key| self.tree_xrefs(id, &key, window, cx));
            }
            "y" => {
                return selected.is_some_and(|key| self.open_global_type(id, &key, window, cx));
            }
            _ => return false,
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return false;
        };
        let moved = state.hex.tree.press(to, &lines);
        let selected = state.hex.tree.selected.clone();
        let side = self.hex.sides.entry(id).or_default();
        side.lines = None;
        side.reveal = true;
        if moved && let Some(key) = selected {
            self.tree_select(id, &key);
        }
        true
    }

    /// Selects tree row `key` and its bytes in pane `id` (in file offsets
    /// if they have no address); a file's headers and tables: its first.
    fn tree_select(&mut self, id: PaneId, key: &Key) {
        if let Some(state) = self.panes.get_mut(&id) {
            state.hex.tree.selected = Some(key.clone());
        }
        let Some(image) = self.hex_image() else {
            return;
        };
        let overlays = Arc::clone(&self.hex.overlays);
        let (Some(overlay), Some(found)) =
            (overlays.get(key.root), hex_tree::resolve(&overlays, key))
        else {
            return;
        };
        let first = if key.steps.is_empty() && overlay.layout.sparse {
            hex_tree::resolve(&overlays, &key.child(hex_tree::Step::Member(0)))
        } else {
            None
        };
        let found = first.unwrap_or(found);
        let last = found.offset + found.size.max(1) - 1;
        let Some(mode) = self.panes.get(&id).map(|s| s.hex.mode) else {
            return;
        };
        let place = |mode: Mode| {
            Some((
                image.position(overlay, mode, found.offset)?,
                image.position(overlay, mode, last)?,
            ))
        };
        let other = match mode {
            Mode::Address => Mode::File,
            Mode::File => Mode::Address,
        };
        let Some((mode, (start, end))) = place(mode)
            .map(|p| (mode, p))
            .or_else(|| place(other).map(|p| (other, p)))
        else {
            return;
        };
        if let Some(state) = self.panes.get_mut(&id) {
            state.hex.switch(&image, mode);
            state.hex.select(end, false);
            state.hex.select(start, true);
            state.hex.target = None;
        }
        self.reveal_hex(id, Reveal::Keys);
        self.hex_moved(id);
    }

    /// The card of the field under the pointer in pane `id`: its path,
    /// type and value, under the pointer.
    fn hex_card(&self, id: PaneId) -> Option<AnyElement> {
        let theme = self.theme;
        let (pane, position, placed) = self.hex.hover.as_ref()?;
        let state = self.panes.get(&id)?;
        if *pane != id || state.hex.dragging {
            return None;
        }
        let image = self.hex_image()?;
        let overlay = self.hex.overlays.get(placed.overlay)?;
        let (file, _) = self.session.as_ref()?.loaded()?;
        let leaf = overlay
            .layout
            .leaves_in(placed.offset..placed.offset + 1)
            .into_iter()
            .find(|l| l.start == placed.offset)?;
        let (space, base) = overlay.anchor.place();
        let read = image.read(
            file,
            space,
            base + leaf.start..base + leaf.end.min(leaf.start + 4096),
        );
        let listing = self.listing.as_ref();
        let session = self.session.as_ref();
        let name = |address: u64| {
            listing?
                .shown_name(address, session?.overlay())
                .map(str::to_owned)
        };
        let value = leaf.node.value(&read, image.little(), &name);
        let path = match (overlay.source, leaf.path.is_empty()) {
            (_, true) => overlay.name.clone(),
            (Source::Header, false) => leaf.path.clone(),
            (Source::Program | Source::Debug | Source::User, false) => {
                format!("{}.{}", overlay.name, leaf.path)
            }
        };
        let b = state.bounds.get();
        let row_h = self.row(self.settings.listing_line_height);
        let width = f32::from(self.z(360.0));
        let x = f32::from(position.x - b.origin.x)
            .min(f32::from(b.size.width) - width - f32::from(self.z(SCROLLBAR)) - 4.0)
            .max(0.0);
        let below = f32::from(position.y - b.origin.y) + row_h;
        let height = 2.0 * row_h + f32::from(self.z(12.0));
        let y = if below + height > f32::from(b.size.height) {
            (below - 2.0 * row_h - height).max(0.0)
        } else {
            below
        };
        Some(
            div()
                .absolute()
                .left(px(x))
                .top(px(y))
                .w(px(width))
                .px(self.z(10.0))
                .py(self.z(6.0))
                .flex()
                .flex_col()
                .bg(hsla(solid(theme.panel)))
                .border_1()
                .border_color(hsla(theme.border_variant))
                .rounded(self.z(6.0))
                .shadow_lg()
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .gap(self.z(12.0))
                        .whitespace_nowrap()
                        .child(
                            div()
                                .min_w_0()
                                .overflow_hidden()
                                .text_ellipsis()
                                .font_weight(gpui_kit::FontWeight::BOLD)
                                .text_color(hsla(theme.text))
                                .child(path),
                        )
                        .child(
                            div()
                                .flex_none()
                                .text_color(hsla(theme.type_))
                                .child(leaf.node.ty.clone()),
                        ),
                )
                .child(
                    div()
                        .whitespace_nowrap()
                        .overflow_hidden()
                        .text_ellipsis()
                        .text_color(hsla(if value.starts_with('"') {
                            theme.string
                        } else {
                            theme.text
                        }))
                        .child(value),
                )
                .into_any_element(),
        )
    }
}

/// What a pointer under the mouse is on.
#[derive(Clone, Copy, Debug)]
enum HexHit {
    /// The overview strip, this far down (0–1).
    Strip(f32),
    /// A line and column of the rows.
    Bytes {
        /// The line.
        line: u64,
        /// The column.
        col: usize,
    },
}
