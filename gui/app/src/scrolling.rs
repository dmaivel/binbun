//! Every scrolling surface's wheel and frames, one way: a wheel's notches
//! eased over the configured duration, a touchpad's pixels at once, keys
//! at once ([`Scroller`]). Line surfaces (the listing, the C, the map, the
//! tables) scroll by their rows; panels, cards and pickers
//! ([`Area`], [`Workspace::scroll_area`]) by pixels, a notch three of the
//! interface's rows.
//! The code panes' text scrolls sideways too ([`Sideways`]): a touchpad's
//! sideways pixels or Shift with the wheel, a horizontal scrollbar under
//! the text while a line in view overflows, the gutter staying put.

use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use binbun_gui_view::layout::PaneId;
use binbun_gui_view::scroll::{Press, Scroller, Sideways, Wheel};
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, Div, ElementId, MouseButton, MouseDownEvent, MouseMoveEvent, Pixels,
    Point, ScrollDelta, ScrollEvent, Stateful, Window, canvas, div, px,
};

use crate::listing_view::SCROLLBAR;
use crate::theme::hsla;
use crate::workspace::{ROW_PAD, TabKind, Workspace, whole_rows_in};

/// A surface scrolled by pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Area {
    /// A pane's settings.
    Settings(PaneId),
    /// The settings' category list.
    SettingsNav(PaneId),
    /// Go anywhere's, the palette's or the recent files' rows.
    Picker,
    /// The peek card's body.
    Peek,
    /// The start page's recent files.
    Start,
}

/// A pixel surface's scrolling and its sizes as last drawn.
#[derive(Debug, Default)]
pub struct AreaScroll {
    /// Its scrolling, a pixel a line.
    pub scroll: Scroller,
    /// The viewport's height.
    pub viewport: Rc<Cell<f32>>,
    /// The content's height.
    pub content: Rc<Cell<f32>>,
}

impl AreaScroll {
    /// The content's and the viewport's heights, in whole pixels.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a panel's height in pixels"
    )]
    fn sizes(&self) -> (u64, u64) {
        (
            self.content.get().max(0.0).ceil() as u64,
            self.viewport.get().max(1.0).floor() as u64,
        )
    }
}

/// What a wheel or touchpad event gives.
pub fn wheel(e: &ScrollEvent) -> Wheel {
    match e.delta {
        ScrollDelta::Lines(lines) => Wheel::Lines(lines.y),
        ScrollDelta::Pixels(pixels) => Wheel::Pixels(f32::from(pixels.y)),
    }
}

/// What a wheel or touchpad event gives sideways: pixels, right when
/// positive, a wheel's line `row` pixels; with Shift the wheel turns it.
pub fn sideways(e: &ScrollEvent, row: f32) -> f32 {
    let (x, y) = match e.delta {
        ScrollDelta::Lines(lines) => (lines.x * row, lines.y * row),
        ScrollDelta::Pixels(pixels) => (f32::from(pixels.x), f32::from(pixels.y)),
    };
    if e.modifiers.shift { -(x + y) } else { -x }
}

/// A code row's scrolled part: `content`, laid out as from the row's left
/// edge, moved `x` pixels left and shown right of `gutter` only.
pub fn scrolled(gutter: f32, x: f32, content: Div) -> Div {
    div()
        .absolute()
        .top_0()
        .bottom_0()
        .left(px(gutter))
        .right_0()
        .overflow_hidden()
        .child(
            content
                .absolute()
                .top_0()
                .bottom_0()
                .left(px(-gutter - x))
                .right(px(-x)),
        )
}

impl Workspace {
    /// Pane `id`'s sideways scrolling: the view's it shows.
    pub fn sideways_of(&mut self, id: PaneId) -> Option<&mut Sideways> {
        let (ir, hex) = (self.shows_ir(id), self.shows_hex(id));
        let c = matches!(self.layout.active(id), Some(TabKind::C { .. }));
        let state = self.panes.get_mut(&id)?;
        Some(if ir {
            &mut state.ir.side
        } else if c {
            &mut state.c.side
        } else if hex {
            &mut state.hex.side
        } else {
            &mut state.listing.side
        })
    }

    /// The wheel's sideways part in pane `id`, its rows `row` pixels.
    pub fn wheel_sideways(&mut self, id: PaneId, e: &ScrollEvent, row: f32) {
        let dx = sideways(e, row);
        if dx != 0.0
            && let Some(side) = self.sideways_of(id)
        {
            side.scroll_by(dx);
        }
    }

    /// The width pane `id` shows its text in right of `gutter`, as last
    /// drawn.
    pub fn sideways_view(&self, id: PaneId, gutter: f32) -> f32 {
        let width = self
            .panes
            .get(&id)
            .map_or(0.0, |s| f32::from(s.bounds.get().size.width));
        (width - gutter - f32::from(self.z(SCROLLBAR))).max(0.0)
    }

    /// Pane `id`'s text shown right of `gutter`, before its rows are
    /// drawn: the cursor (its place, its band from the text's left edge)
    /// followed. How far the text is scrolled left.
    pub fn follow_sideways(
        &mut self,
        id: PaneId,
        gutter: f32,
        cursor: Option<((u64, u64), (f32, f32))>,
    ) -> f32 {
        let view = self.sideways_view(id, gutter);
        let Some(side) = self.sideways_of(id) else {
            return 0.0;
        };
        side.view = view;
        if let Some((at, band)) = cursor {
            side.follow(at, band);
        }
        side.x
    }

    /// Pane `id`'s rows drawn right of `gutter`, the widest `content`
    /// pixels from the text's left edge: its horizontal scrollbar
    /// ([`Self::sideways_bar`]).
    pub fn measured_sideways(
        &mut self,
        id: PaneId,
        gutter: f32,
        content: f32,
    ) -> Option<AnyElement> {
        let view = self.sideways_view(id, gutter);
        let side = self.sideways_of(id)?;
        side.view = view;
        side.content = content;
        let side = *side;
        self.sideways_bar(&side)
    }

    /// The horizontal scrollbar of `side`, as the vertical one: under the
    /// text, from the gutter to the vertical scrollbar, a 1 px track
    /// border and the thumb; none while it neither scrolls nor overflows.
    fn sideways_bar(&self, side: &Sideways) -> Option<AnyElement> {
        if !side.scrolls() || side.view <= 0.0 {
            return None;
        }
        let theme = self.theme;
        let view = side.view;
        let thumb = side.thumb(self.row(22.0));
        Some(
            div()
                .absolute()
                .bottom_0()
                .right(self.z(SCROLLBAR))
                .w(px(view))
                .h(self.z(SCROLLBAR))
                .bg(hsla(theme.editor))
                .border_t_1()
                .border_color(hsla(theme.scrollbar_track_border))
                .child(
                    div()
                        .absolute()
                        .top_0()
                        .bottom_0()
                        .left(px(thumb.start))
                        .w(px(thumb.len))
                        .bg(hsla(theme.scrollbar_thumb)),
                )
                .into_any_element(),
        )
    }

    /// Where `position` is along pane `id`'s horizontal scrollbar, in
    /// pixels from the track's left end, if it is on it.
    pub fn on_sideways_bar(&mut self, id: PaneId, position: Point<Pixels>) -> Option<f32> {
        let b = self.panes.get(&id)?.bounds.get();
        let bar = f32::from(self.z(SCROLLBAR));
        let side = *self.sideways_of(id)?;
        let x = f32::from(position.x - b.origin.x);
        let y = f32::from(position.y - b.origin.y);
        let right = f32::from(b.size.width) - bar;
        let left = right - side.view;
        (side.scrolls() && y > f32::from(b.size.height) - bar && x >= left && x < right)
            .then_some(x - left)
    }

    /// A press in pane `id`: on its horizontal scrollbar, a left press on
    /// the thumb drags it from where it was taken, beside it a view's
    /// width that way; whether it was on it.
    pub fn sideways_down(&mut self, id: PaneId, e: &MouseDownEvent) -> bool {
        let Some(at) = self.on_sideways_bar(id, e.position) else {
            return false;
        };
        let least = self.row(22.0);
        if e.button == MouseButton::Left
            && let Some(side) = self.sideways_of(id)
        {
            match side.thumb(least).press(at) {
                Press::Before => side.page(false),
                Press::After => side.page(true),
                Press::On(grab) => self.sideways_drag = Some((id, grab)),
            }
        }
        true
    }

    /// A move in pane `id` dragging its horizontal scrollbar; whether it
    /// was such a drag.
    pub fn sideways_move(&mut self, id: PaneId, e: &MouseMoveEvent) -> bool {
        let Some((_, grab)) = self.sideways_drag.filter(|&(pane, _)| pane == id) else {
            return false;
        };
        if !e.dragging() {
            return false;
        }
        let Some(b) = self.panes.get(&id).map(|s| s.bounds.get()) else {
            return false;
        };
        let right = f32::from(b.size.width) - f32::from(self.z(SCROLLBAR));
        let x = f32::from(e.position.x - b.origin.x);
        let least = self.row(22.0);
        if let Some(side) = self.sideways_of(id) {
            side.drag_thumb(x - (right - side.view) - grab, least);
        }
        true
    }

    /// `content` in a viewport of `area` that the wheel scrolls (eased) by
    /// pixels; the caller sizes it (`flex_1`, `max_h`, `h`).
    pub fn scroll_area(
        &mut self,
        area: Area,
        id: impl Into<ElementId>,
        content: impl IntoElement,
        cx: &mut Context<Self>,
    ) -> Stateful<Div> {
        let state = self.areas.entry(area).or_default();
        let viewport = Rc::clone(&state.viewport);
        let measured = Rc::clone(&state.content);
        let y = state.scroll.pixels();
        let notch = self.row(self.ui_line() + ROW_PAD);
        div()
            .id(id)
            .relative()
            .overflow_hidden()
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, _, cx| {
                if let Some(a) = this.areas.get_mut(&area) {
                    let (total, visible) = a.sizes();
                    let given = match wheel(e) {
                        Wheel::Lines(lines) => Wheel::Lines(lines * notch),
                        pixels @ Wheel::Pixels(_) => pixels,
                    };
                    a.scroll.wheel(given, 1.0, total, visible);
                    cx.stop_propagation();
                    cx.notify();
                }
            }))
            .child(
                canvas(
                    move |b, _, _| viewport.set(f32::from(b.size.height)),
                    |_, (), _, _| {},
                )
                .absolute()
                .size_full(),
            )
            .child(
                div()
                    .relative()
                    .top(px(-y))
                    .child(
                        canvas(
                            move |b, _, _| measured.set(f32::from(b.size.height)),
                            |_, (), _, _| {},
                        )
                        .absolute()
                        .size_full(),
                    )
                    .child(content),
            )
    }

    /// Scrolls `area` at once so the band `top..top + height` (pixels of
    /// its content) is visible: a key moving a selection.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a panel's pixels"
    )]
    pub fn reveal_in_area(&mut self, area: Area, top: f32, height: f32) {
        let Some(a) = self.areas.get_mut(&area) else {
            return;
        };
        let (total, visible) = a.sizes();
        a.scroll.smooth.stop();
        let y = a.scroll.pixels();
        let viewport = a.viewport.get();
        let to = if top < y {
            top
        } else if top + height > y + viewport {
            top + height - viewport
        } else {
            return;
        };
        let max = total.saturating_sub(visible);
        a.scroll.anchor.line = (to.max(0.0).round() as u64).min(max);
        a.scroll.anchor.offset = 0.0;
    }

    /// Back to the top of `area`.
    pub fn reset_area(&mut self, area: Area) {
        if let Some(a) = self.areas.get_mut(&area) {
            a.scroll.reset();
        }
    }

    /// `area` scrolled at once so its content's pixel `top` is at the top
    /// (as far as the content goes).
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a panel's pixels"
    )]
    pub fn scroll_area_to(&mut self, area: Area, top: f32) {
        let Some(a) = self.areas.get_mut(&area) else {
            return;
        };
        let (total, visible) = a.sizes();
        a.scroll.smooth.stop();
        a.scroll.anchor.line = (top.max(0.0).round() as u64).min(total.saturating_sub(visible));
        a.scroll.anchor.offset = 0.0;
    }

    /// One frame of every surface's wheel scrolling; asks for the next
    /// frame while one still moves.
    pub fn step_smooth(&mut self, window: &mut Window) {
        let moving = self.panes.values().any(|s| {
            s.listing.scroll.smooth.is_moving()
                || s.c.scroll.smooth.is_moving()
                || s.list.scroll.smooth.is_moving()
                || s.ir.scroll.smooth.is_moving()
                || s.unified.scroll.smooth.is_moving()
        }) || self
            .sidebar
            .as_ref()
            .is_some_and(|s| s.scroll.smooth.is_moving())
            || self.areas.values().any(|a| a.scroll.smooth.is_moving());
        if !moving {
            self.smooth_at = None;
            return;
        }
        let now = Instant::now();
        let dt = self
            .smooth_at
            .map_or(Duration::from_micros(16_667), |at| now - at);
        // Frame pacing as the window sees it (the first frame of a scroll
        // has no interval).
        if self.smooth_at.is_some() {
            trace!("scroll frame {:.2} ms", dt.as_secs_f64() * 1e3);
        }
        self.smooth_at = Some(now);
        let duration = if self.settings.smooth_scroll {
            Duration::from_millis(u64::from(self.settings.smooth_scroll_ms))
        } else {
            Duration::ZERO
        };
        let l_row = self.row(self.settings.listing_line_height);
        let c_row = self.row(self.settings.c_line_height);
        let ui_row = self.row(self.ui_line() + ROW_PAD);
        let l_total = self.listing.as_ref().map_or(0, |l| l.len());
        let ids: Vec<PaneId> = self.panes.keys().copied().collect();
        for id in ids {
            let c_total = self
                .layout
                .active(id)
                .and_then(|k| self.document(k))
                .map_or(0, |d| d.lines.len() as u64);
            let l_rows = self.rows(id, self.settings.listing_line_height);
            let c_rows = self.rows(id, self.settings.c_line_height);
            let list_rows = self.rows(id, self.ui_line() + ROW_PAD).saturating_sub(1);
            let ir_total = self.ir_total(id);
            let Some(state) = self.panes.get_mut(&id) else {
                continue;
            };
            let list_total = state.list.rows.len() as u64;
            let unified_total = state.unified.flat.as_ref().map_or(0, |f| f.len() as u64);
            state
                .unified
                .scroll
                .frame(dt, duration, l_row, unified_total, l_rows);
            state
                .listing
                .scroll
                .frame(dt, duration, l_row, l_total, l_rows);
            state.c.scroll.frame(dt, duration, c_row, c_total, c_rows);
            state.ir.scroll.frame(dt, duration, l_row, ir_total, l_rows);
            state
                .list
                .scroll
                .frame(dt, duration, ui_row, list_total, list_rows.max(1));
        }
        if let Some(s) = &mut self.sidebar {
            let height = f32::from(s.bounds.get().size.height);
            let visible = whole_rows_in(height.max(1.0), ui_row);
            if s.scroll.smooth.is_moving() {
                s.scroll
                    .frame(dt, duration, ui_row, s.rows.len() as u64, visible);
                let line = f32::from(u16::try_from(s.scroll.anchor.line).unwrap_or(u16::MAX));
                trace!(
                    "scroll map {:.2} px after {:.1} ms",
                    line * ui_row + s.scroll.anchor.offset,
                    dt.as_secs_f64() * 1e3
                );
            }
        }
        for a in self.areas.values_mut() {
            let (total, visible) = a.sizes();
            a.scroll.frame(dt, duration, 1.0, total, visible);
        }
        window.request_animation_frame();
    }
}
