//! The feature map: a strip at the right of the panes, or a band above
//! them (`window.feature_map`), standing for the whole image
//! in address order with the gaps between segments compressed
//! (`binbun_gui_view::feature_map::Scale`). Its colours are the hex
//! view's overview in address mode, each part's kind as its feature on
//! the theme's `--map-*` roles: the overview is made once per analysis,
//! its bands once per size and theme. Over them: the bookmarks (a notch
//! on one side), the current search's hits (a notch on the other), the
//! others' places in a session (their ticks across the band, edged in
//! the panel's colour) and the cursor (an accent bar); in a lane beside
//! the band on the panes' side, an arrow at each, in
//! each person's colour and the cursor's in the accent. A click takes the
//! focused pane's sync group there; hovering names what is there; its
//! context menu hides it or moves it.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::Arc;

use binbun_gui_view::collab::Cursor;
use binbun_gui_view::context::Surface;
use binbun_gui_view::feature_map::{Across, Feature, Scale, band, column, libraries, runs};
use binbun_gui_view::hex::{HexImage, Mode};
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::settings::{FeatureMap, Setting};
use binbun_gui_view::tabs::Opening;
use gpui_kit::prelude::*;
use gpui_kit::{
    Anchor, AnyElement, Bounds, Context, Div, MouseButton, MouseDownEvent, MouseMoveEvent, Pixels,
    Point, Window, anchored, canvas, deferred, div, fill, point, px, size,
};

use crate::calls_view::Quad;
use crate::collab::TickStyle;
use crate::hex_view::{BAND, Overview};
use crate::panes::{FRAME, measured};
use crate::search_view::{FindKind, Rows};
use crate::sidebar::tabular;
use crate::theme::{Theme, hsla, solid, with_alpha};
use crate::workspace::{TabKind, Workspace};

/// The band's thickness (logical).
pub const THICKNESS: f32 = 14.0;

/// The thickness of the lane of the markers' arrows beside the band
/// (logical).
const LANE: f32 = 6.0;

/// What the bands were drawn for besides the overview.
#[derive(Clone, Copy, PartialEq)]
struct BandsKey {
    /// The strip's length and thickness (pixels).
    length: f32,
    thickness: f32,
    vertical: bool,
    theme: *const Theme,
}

/// What the search's marks were made from: the pane, its search's
/// matches (how many, the first and last), the strip's length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HitsKey {
    pane: PaneId,
    found: (usize, u64, u64),
    length: u64,
}

/// The current search's matches, for the marks.
enum Matches {
    /// No search.
    None,
    /// The same as the marks were made from.
    Same,
    /// Others: their key and addresses.
    New(HitsKey, Vec<u64>),
}

/// Each part's feature of an overview (`None`: a gap).
type Column = Arc<Vec<Option<Feature>>>;

/// The feature map's state.
#[derive(Default)]
pub struct FeatureMapUi {
    /// The strip's bounds as last drawn.
    bounds: Rc<Cell<Bounds<Pixels>>>,
    /// Its bands as last drawn, and what they were made from: a run of
    /// parts of one feature one quad.
    bands: Option<(Column, BandsKey, Arc<Vec<Quad>>)>,
    /// Each part's feature, for the overview and the library functions
    /// it is of.
    column: Option<(Overview, Arc<BTreeSet<u64>>, Column)>,
    /// The entries of the functions library signatures name (replaced
    /// when they change, so the column is made again).
    library: Arc<BTreeSet<u64>>,
    /// The pixels along the strip with a match of the current search.
    hits: Option<(HitsKey, Arc<Vec<u64>>)>,
    /// The pointer over it: where (the window's), and the address there.
    hover: Option<(Point<Pixels>, u64)>,
    /// Where it was when hidden (shown there again).
    hidden_from: Option<FeatureMap>,
}

impl Workspace {
    /// The functions library signatures name are `library` now (the
    /// map's): the feature map's column is made again if they changed.
    pub(crate) fn set_library_functions(&mut self, library: BTreeSet<u64>) {
        if *self.feature_map.library != library {
            self.feature_map.library = Arc::new(library);
        }
    }

    /// The image's mapped space laid out on the strip: the hex view's
    /// address blocks end to end.
    fn feature_scale(image: &HexImage) -> Scale {
        Scale::new(image.blocks())
    }

    /// View → Feature Map: hides it, or shows it where it was.
    pub fn toggle_feature_map(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let now = self.settings.feature_map;
        let next = if now == FeatureMap::Off {
            self.feature_map.hidden_from.take().unwrap_or_default()
        } else {
            self.feature_map.hidden_from = Some(now);
            FeatureMap::Off
        };
        self.feature_map.hover = None;
        self.set_setting(
            "window.feature_map",
            &Setting::Text(next.name().to_owned()),
            window,
            cx,
        );
    }

    /// Puts the feature map at the top, or back at the right.
    pub fn move_feature_map(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let next = match self.settings.feature_map {
            FeatureMap::Top => FeatureMap::Right,
            FeatureMap::Right | FeatureMap::Off => FeatureMap::Top,
        };
        self.feature_map.hover = None;
        self.set_setting(
            "window.feature_map",
            &Setting::Text(next.name().to_owned()),
            window,
            cx,
        );
    }

    /// The strip's length and thickness (pixels, as last drawn) and
    /// whether it runs down.
    fn feature_extent(&self) -> (f32, f32, bool) {
        let b = self.feature_map.bounds.get();
        let (w, h) = (f32::from(b.size.width), f32::from(b.size.height));
        if self.settings.feature_map == FeatureMap::Top {
            (w, h, false)
        } else {
            (h, w, true)
        }
    }

    /// Where the band and the arrows' lane are across the strip.
    pub(crate) fn feature_across(&self) -> Across {
        let (_, thickness, vertical) = self.feature_extent();
        Across::new(thickness, f32::from(self.z(LANE)).round(), vertical)
    }

    /// How far along the strip `position` (the window's) is, in pixels.
    fn feature_along(&self, position: Point<Pixels>) -> f32 {
        let b = self.feature_map.bounds.get();
        if self.settings.feature_map == FeatureMap::Top {
            f32::from(position.x - b.origin.x)
        } else {
            f32::from(position.y - b.origin.y)
        }
    }

    /// The address drawn under `position`.
    fn feature_address(&self, position: Point<Pixels>) -> Option<u64> {
        let image = self.hex_image()?;
        let (length, _, _) = self.feature_extent();
        Self::feature_scale(&image).address_at(self.feature_along(position), length)
    }

    /// The bands of `overview` along the strip: made again only when its
    /// column ([`Self::feature_column`]), the strip's size or the theme
    /// change.
    fn feature_bands(&mut self, image: &HexImage, overview: &Overview) -> Arc<Vec<Quad>> {
        let theme = self.theme;
        let (length, thickness, vertical) = self.feature_extent();
        let strip = self.feature_across();
        let key = BandsKey {
            length,
            thickness,
            vertical,
            theme: std::ptr::from_ref(theme),
        };
        let features = self.feature_column(image, overview);
        if let Some((of, made, bands)) = &self.feature_map.bands
            && Arc::ptr_eq(of, &features)
            && *made == key
        {
            return Arc::clone(bands);
        }
        let bands: Arc<Vec<Quad>> = Arc::new(
            runs(features.iter().copied())
                .into_iter()
                .map(|(run, feature)| {
                    let (at, extent) = band(&run, features.len(), length);
                    let color = with_alpha(theme.feature(feature), BAND);
                    across(
                        vertical,
                        at,
                        extent,
                        strip.band + 1.0,
                        strip.thickness - 2.0,
                        color,
                    )
                })
                .collect(),
        );
        self.feature_map.bands = Some((features, key, Arc::clone(&bands)));
        bands
    }

    /// Each part's feature of `overview` (the hex view's of `image`), a
    /// part of functions' code mostly library functions' a library's:
    /// made once per overview and set of library functions.
    fn feature_column(
        &mut self,
        image: &HexImage,
        overview: &Overview,
    ) -> Arc<Vec<Option<Feature>>> {
        let library = Arc::clone(&self.feature_map.library);
        if let Some((of, by, features)) = &self.feature_map.column
            && Arc::ptr_eq(of, overview)
            && Arc::ptr_eq(by, &library)
        {
            return Arc::clone(features);
        }
        let mut features = column(overview);
        if !library.is_empty()
            && let Some(listing) = &self.listing
        {
            let parts = features.len();
            libraries(
                &mut features,
                |part| image.part_rows(Mode::Address, parts, part).collect(),
                |address| {
                    let (_, entry) = listing.function_of(address)?;
                    Some(library.contains(&entry))
                },
            );
        }
        let features = Arc::new(features);
        self.feature_map.column = Some((Arc::clone(overview), library, Arc::clone(&features)));
        features
    }

    /// The current search's matches: the focused pane's results tab's,
    /// else its find bar's.
    fn search_matches(&self, image: &HexImage) -> Matches {
        self.search_addresses(image).unwrap_or(Matches::None)
    }

    fn search_addresses(&self, image: &HexImage) -> Option<Matches> {
        let id = self.layout.focused();
        let (length, _, _) = self.feature_extent();
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a strip's pixels"
        )]
        let length = length.max(0.0) as u64;
        let made = self.feature_map.hits.as_ref().map(|(key, _)| *key);
        let key = |found: (usize, u64, u64)| HitsKey {
            pane: id,
            found,
            length,
        };
        if let Some(TabKind::Found(n)) = self.layout.active(id) {
            let tab = self.search.tabs.get(n)?;
            let found = match &tab.rows {
                Rows::Text(rows) => {
                    let rows = rows.rows();
                    (
                        rows.len(),
                        rows.first().map_or(0, |h| h.address),
                        rows.last().map_or(0, |h| h.address),
                    )
                }
                Rows::Bytes(hits, _) => (
                    hits.len(),
                    hits.first().map_or(0, |h| h.at),
                    hits.last().map_or(0, |h| h.at),
                ),
            };
            if made == Some(key(found)) {
                return Some(Matches::Same);
            }
            let addresses = match &tab.rows {
                Rows::Text(rows) => rows.rows().iter().map(|h| h.address).collect(),
                Rows::Bytes(hits, false) => hits.iter().map(|h| h.at).collect(),
                Rows::Bytes(hits, true) => hits
                    .iter()
                    .filter_map(|h| image.convert(h.at, Mode::File, Mode::Address))
                    .collect(),
            };
            return Some(Matches::New(key(found), addresses));
        }
        let bar = self.search.bars.get(&id)?;
        let hits = bar.found.hits();
        let found = (
            hits.len(),
            hits.first().map_or(0, |h| h.line),
            hits.last().map_or(0, |h| h.line),
        );
        if made == Some(key(found)) {
            return Some(Matches::Same);
        }
        let mut lines: Vec<u64> = hits.iter().map(|h| h.line).collect();
        lines.dedup();
        let addresses = match bar.kind.as_ref()? {
            FindKind::Listing => {
                let listing = self.listing.as_ref()?;
                lines
                    .iter()
                    .filter_map(|&n| listing.line(n).map(|l| l.address))
                    .collect()
            }
            FindKind::C(function, view) => {
                let document = self.session.as_ref()?.document(*function, *view)?;
                lines
                    .iter()
                    .filter_map(|&n| {
                        let line = document.lines.get(usize::try_from(n).ok()?)?;
                        line.addresses.first().copied()
                    })
                    .collect()
            }
            FindKind::Hex(Mode::Address) => lines,
            FindKind::Hex(Mode::File) => lines
                .iter()
                .filter_map(|&at| image.convert(at, Mode::File, Mode::Address))
                .collect(),
        };
        Some(Matches::New(key(found), addresses))
    }

    /// The pixels along the strip with a match of the current search
    /// (made again when the matches or the strip's length change).
    fn feature_hits(&mut self, image: &HexImage, scale: &Scale) -> Arc<Vec<u64>> {
        let (length, _, _) = self.feature_extent();
        match self.search_matches(image) {
            Matches::New(key, addresses) => {
                let mut pixels: Vec<u64> = addresses
                    .iter()
                    .filter_map(|&a| scale.pixel(a, length))
                    .collect();
                pixels.sort_unstable();
                pixels.dedup();
                let pixels = Arc::new(pixels);
                self.feature_map.hits = Some((key, Arc::clone(&pixels)));
                pixels
            }
            Matches::Same => self
                .feature_map
                .hits
                .as_ref()
                .map(|(_, pixels)| Arc::clone(pixels))
                .unwrap_or_default(),
            Matches::None => Arc::default(),
        }
    }

    /// The marks over the bands: the bookmarks (each in its person's
    /// colour, one's own muted) and the threads on one side, the search's
    /// matches on the other, the cursor across, its arrow in the lane.
    fn feature_marks(&mut self, image: &HexImage, scale: &Scale) -> Vec<Quad> {
        let theme = self.theme;
        let (length, _, vertical) = self.feature_extent();
        let strip = self.feature_across();
        let (band, thickness) = (strip.band, strip.thickness);
        let half = (thickness / 2.0).floor();
        let mut quads = Vec::new();
        #[expect(clippy::cast_precision_loss, reason = "a strip's pixels")]
        let at = |p: u64| p as f32;
        // Others' first, so one's own lies over theirs at one spot.
        let mut marks: Vec<(u64, u32)> = Vec::new();
        if let Some(session) = &self.session {
            for (&key, theirs) in session.others_bookmarks() {
                let color = self.person_rgba(key);
                marks.extend(theirs.keys().map(|&a| (a, color)));
            }
            let mine = session
                .overlay()
                .bookmarks
                .keys()
                .chain(session.private_bookmarks().keys());
            marks.extend(mine.map(|&a| (a, theme.text)));
        }
        for (address, color) in marks {
            if let Some(p) = scale.pixel(address, length) {
                quads.push(across(vertical, at(p), 2.0, band, half, color));
            }
        }
        for thread in &self.threads.all {
            if let Some(p) = thread.anchor.address().and_then(|a| scale.pixel(a, length)) {
                let color = if thread.resolved {
                    theme.text_placeholder
                } else {
                    theme.hint
                };
                quads.push(across(vertical, at(p), 2.0, band, half, solid(color)));
            }
        }
        let hit = solid(theme.active_match);
        let pixels = self.feature_hits(image, scale);
        let mut run: Option<(u64, u64)> = None;
        let flush = |run: (u64, u64), quads: &mut Vec<Quad>| {
            let extent = at(run.1 - run.0 + 1).max(2.0);
            quads.push(across(
                vertical,
                at(run.0),
                extent,
                band + half,
                thickness - half,
                hit,
            ));
        };
        for &p in pixels.iter() {
            run = match run {
                Some((start, end)) if p == end + 1 => Some((start, p)),
                Some(done) => {
                    flush(done, &mut quads);
                    Some((p, p))
                }
                None => Some((p, p)),
            };
        }
        if let Some(done) = run {
            flush(done, &mut quads);
        }
        let id = self.layout.focused();
        if let Some(p) = self
            .cursor_address(id)
            .or(self.shared)
            .and_then(|a| scale.pixel(a, length))
        {
            let p = at(p).min(length - 2.0).max(0.0);
            let edge = solid(theme.panel);
            quads.push(across(vertical, p - 1.0, 1.0, band, thickness, edge));
            quads.push(across(vertical, p + 2.0, 1.0, band, thickness, edge));
            quads.push(across(vertical, p, 2.0, band, thickness, theme.accent));
            for (from, extent, row) in strip.arrow(p + 1.0) {
                quads.push(across(vertical, from, extent, row, 1.0, theme.accent));
            }
        }
        quads
    }

    /// The feature map's container, running down (`vertical`) or along:
    /// an island among the others (its frame and hairline added to its
    /// width), or a strip with a hairline on the panes' side.
    fn feature_strip(&self, vertical: bool) -> Div {
        let across = self.z(THICKNESS + LANE);
        if self.settings.islands {
            let island = self.island().relative().flex_none();
            let across = across + (self.z(FRAME) + self.island_inset()) * 2.0;
            if vertical {
                island.w(across)
            } else {
                island.h(across)
            }
        } else {
            let strip = div()
                .relative()
                .flex_none()
                .overflow_hidden()
                .border_color(hsla(self.theme.border));
            if vertical {
                strip.h_full().w(across).border_l_1()
            } else {
                strip.w_full().h(across).border_b_1()
            }
        }
    }

    /// The feature map, if shown (a binary open, its image parsed): the
    /// element, and whether it runs down (at the right) or along (at the
    /// top).
    pub fn render_feature_map(&mut self, cx: &mut Context<Self>) -> Option<(bool, AnyElement)> {
        let placement = self.settings.feature_map;
        if placement == FeatureMap::Off || self.session.is_none() {
            return None;
        }
        let image = self.hex_image()?;
        let overview = self.hex_overview(&image, Mode::Address)?;
        let scale = Self::feature_scale(&image);
        let (length, _, vertical) = self.feature_extent();
        let bands = self.feature_bands(&image, &overview);
        let marks = self.feature_marks(&image, &scale);
        let total = scale.total();
        #[expect(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            reason = "a fraction of the strip"
        )]
        let fraction = move |cursor: &Cursor| {
            let offset = scale.offset(cursor.address)?;
            Some((offset as f64 / total.max(1) as f64) as f32)
        };
        let id = self.layout.focused();
        let style = TickStyle::Band(self.feature_across());
        let ticks = self.person_ticks(id, length, vertical, style, fraction, cx);
        let theme = self.theme;
        let element = self
            .feature_strip(vertical)
            .id("feature-map")
            .bg(hsla(theme.under(theme.panel)))
            .child(
                measured(Rc::clone(&self.feature_map.bounds))
                    .absolute()
                    .size_full(),
            )
            .child(
                canvas(
                    |_, _, _| {},
                    move |bounds, (), window, _| {
                        for q in bands.iter().chain(&marks) {
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
            .children(ticks)
            .children(self.island_edge())
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, e: &MouseDownEvent, window, cx| {
                    window.prevent_default();
                    cx.stop_propagation();
                    if let Some(address) = this.feature_address(e.position) {
                        this.feature_jump(address, window, cx);
                    }
                    cx.notify();
                }),
            )
            .on_mouse_down(
                MouseButton::Right,
                cx.listener(|this, e: &MouseDownEvent, window, cx| {
                    cx.stop_propagation();
                    this.feature_map.hover = None;
                    this.open_context_menu(Surface::FeatureMap, e.position, window, cx);
                }),
            )
            .on_mouse_move(cx.listener(|this, e: &MouseMoveEvent, _, cx| {
                let hover = this.feature_address(e.position).map(|a| (e.position, a));
                if this.context_menu.is_none() && hover != this.feature_map.hover {
                    this.feature_map.hover = hover;
                    cx.notify();
                }
            }))
            .on_hover(cx.listener(|this, hovered: &bool, _, cx| {
                if !*hovered && this.feature_map.hover.take().is_some() {
                    cx.notify();
                }
            }))
            .into_any_element();
        Some((vertical, element))
    }

    /// A click on the feature map: the focused pane (a code pane: its
    /// sync group with it) goes there, as a jump; from a list, the code
    /// opens as a click in a list opens it.
    fn feature_jump(&mut self, address: u64, window: &mut Window, cx: &mut Context<Self>) {
        let id = self.layout.focused();
        self.unfollow();
        if matches!(
            self.layout.active(id),
            Some(TabKind::Listing | TabKind::C { .. })
        ) {
            self.jump(address, cx);
            self.focus_pane(id, window, cx);
        } else {
            self.open_from_list(id, address, Opening::Linked { focus: true }, window, cx);
        }
    }

    /// What is at `address`, as the feature map's tooltip names it: its
    /// function, else its item's name, else its section.
    fn feature_name(&self, image: &HexImage, address: u64) -> Option<String> {
        let listing = self.listing.as_ref()?;
        let overlay = self.session.as_ref()?.overlay();
        let readable = |name: &str| {
            self.demangled
                .get(name)
                .and_then(Clone::clone)
                .unwrap_or_else(|| name.to_owned())
        };
        if let Some((_, entry)) = listing.function_of(address)
            && let Some(name) = listing.shown_name(entry, overlay)
        {
            return Some(readable(name));
        }
        listing
            .line(listing.line_of(address))
            .filter(|line| line.address <= address)
            .and_then(|line| listing.shown_name(line.address, overlay))
            .map(readable)
            .or_else(|| image.section(address).map(str::to_owned))
    }

    /// The tooltip naming what is under the pointer on the feature map:
    /// its kind's colour, its name and its address.
    pub fn render_feature_tip(&mut self) -> Option<AnyElement> {
        let (position, address) = self.feature_map.hover?;
        if self.context_menu.is_some() || self.settings.feature_map == FeatureMap::Off {
            return None;
        }
        let image = self.hex_image()?;
        let overview = self.hex_overview(&image, Mode::Address)?;
        let features = self.feature_column(&image, &overview);
        let (length, _, vertical) = self.feature_extent();
        let along = self.feature_along(position);
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss,
            reason = "a part of the strip"
        )]
        let part = ((along / length.max(1.0)) * features.len() as f32).max(0.0) as usize;
        let feature = features
            .get(part.min(features.len().saturating_sub(1)))
            .copied()
            .flatten();
        let theme = self.theme;
        let name = self.feature_name(&image, address);
        let card = div()
            .flex()
            .items_center()
            .gap(self.z(6.0))
            .px(self.z(8.0))
            .py(self.z(4.0))
            .bg(hsla(solid(theme.panel)))
            .border_1()
            .border_color(hsla(theme.border_variant))
            .rounded(self.z(4.0))
            .shadow_md()
            .whitespace_nowrap()
            .when_some(feature, |d, f| {
                d.child(
                    div()
                        .flex_none()
                        .size(self.z(8.0))
                        .rounded(self.z(2.0))
                        .bg(hsla(theme.feature(f))),
                )
            })
            .children(name.map(|n| div().text_color(hsla(theme.text)).child(n)))
            .child(
                div()
                    .text_color(hsla(theme.text_muted))
                    .font_features(tabular())
                    .child(format!("{address:X}")),
            );
        // Beside the strip: left of the pointer at the right, under it at
        // the top (kept in the window).
        let (at, corner) = if vertical {
            (
                point(position.x - px(12.0), position.y - px(10.0)),
                Anchor::TopRight,
            )
        } else {
            (point(position.x, position.y + px(18.0)), Anchor::TopLeft)
        };
        Some(
            deferred(
                anchored()
                    .position(at)
                    .anchor(corner)
                    .snap_to_window_with_margin(px(8.0))
                    .child(card),
            )
            .with_priority(1)
            .into_any_element(),
        )
    }
}

/// A quad across the strip: `extent` long from `at` along it, from
/// `from` across it, `width` wide.
fn across(vertical: bool, at: f32, extent: f32, from: f32, width: f32, color: u32) -> Quad {
    if vertical {
        Quad {
            x: from,
            y: at,
            w: width,
            h: extent,
            color,
        }
    } else {
        Quad {
            x: at,
            y: from,
            w: extent,
            h: width,
            color,
        }
    }
}
