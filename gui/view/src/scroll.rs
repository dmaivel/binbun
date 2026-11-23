//! A scroll position that stays exact over any number of lines, smooth
//! scrolling for a wheel's notches, and the two together ([`Scroller`]):
//! what every scrolling surface of the GUI keeps (the code views and
//! tables by lines; panels, cards and lists by pixels, each pixel a line).
//!
//! GPUI positions content in `f32` pixels: past 2^24 px (about 900k lines
//! of 18 px) one step is 2 px. A viewport instead keeps its first visible
//! line as a `u64` and only the offset inside that line as pixels; the
//! renderer draws the visible lines at `-offset + k * row` and never sees
//! a large coordinate.

use std::time::Duration;

/// The top of a viewport: the first visible line and how far it is
/// scrolled up, in pixels (`0 <= offset < row`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ScrollAnchor {
    /// The first visible line.
    pub line: u64,
    /// How many pixels of it are above the viewport.
    pub offset: f32,
}

impl ScrollAnchor {
    /// The highest first line for `total` lines with `visible` rows shown.
    pub fn max_line(total: u64, visible: u64) -> u64 {
        total.saturating_sub(visible.max(1))
    }

    /// Scrolled by `dy` pixels (down when positive), clamped to the
    /// content.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "whole lines of a finite delta, clamped to the content"
    )]
    pub fn scroll_by(&mut self, dy: f64, row: f32, total: u64, visible: u64) {
        let row = f64::from(row);
        // Whole lines are taken out of the delta first, so the result is
        // exact however far the viewport is.
        let whole = (f64::from(self.offset) + dy).div_euclid(row);
        let rest = (f64::from(self.offset) + dy).rem_euclid(row);
        let max = Self::max_line(total, visible);
        let (line, clamped) = if whole < 0.0 {
            let back = (-whole) as u64;
            (self.line.saturating_sub(back), self.line < back)
        } else {
            let line = self.line.saturating_add(whole as u64);
            (line.min(max), line > max)
        };
        self.line = line;
        self.offset = if clamped || line == max {
            0.0
        } else {
            rest as f32
        };
    }

    /// Scrolled so `line` is visible, with `margin` lines around it where
    /// possible; unchanged if it already is.
    pub fn reveal(&mut self, line: u64, total: u64, visible: u64, margin: u64) {
        let visible = visible.max(1);
        let margin = margin.min(visible / 3);
        if line < self.line + margin || (line == self.line && self.offset > 0.0) {
            self.line = line.saturating_sub(margin);
            self.offset = 0.0;
        } else if line + margin + 1 >= self.line + visible {
            self.line = (line + margin + 1).saturating_sub(visible - 1);
            self.offset = 0.0;
        }
        self.line = self.line.min(Self::max_line(total, visible));
    }

    /// Scrolled so `line` is the third row (two lines of context above it),
    /// where a jump puts its target.
    pub fn focus(&mut self, line: u64, total: u64, visible: u64) {
        self.line = line.saturating_sub(2).min(Self::max_line(total, visible));
        self.offset = 0.0;
    }

    /// Where the viewport is, from 0 (top) to 1 (bottom), for a scrollbar.
    #[expect(
        clippy::cast_precision_loss,
        reason = "a fraction for a scrollbar's pixels"
    )]
    pub fn fraction(&self, total: u64, visible: u64) -> f64 {
        let max = Self::max_line(total, visible);
        if max == 0 {
            0.0
        } else {
            (self.line as f64 / max as f64).clamp(0.0, 1.0)
        }
    }

    /// Scrolled to `fraction` of the content (a scrollbar drag).
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a scrollbar's pixel resolution, clamped to the content"
    )]
    pub fn set_fraction(&mut self, fraction: f64, total: u64, visible: u64) {
        let max = Self::max_line(total, visible);
        self.line = ((fraction.clamp(0.0, 1.0) * max as f64).round() as u64).min(max);
        self.offset = 0.0;
    }

    /// A page of `visible` lines further down (`down`) or up (a click on
    /// the track beside the thumb).
    pub fn page(&mut self, down: bool, total: u64, visible: u64) {
        let visible = visible.max(1);
        self.line = if down {
            self.line.saturating_add(visible)
        } else {
            self.line.saturating_sub(visible)
        }
        .min(Self::max_line(total, visible));
        self.offset = 0.0;
    }

    /// Its scrollbar's thumb on a track `track` pixels long.
    #[expect(clippy::cast_precision_loss, reason = "a scrollbar's pixels")]
    pub fn thumb(&self, track: f32, total: u64, visible: u64, least: f32) -> Thumb {
        Thumb::new(
            track,
            visible as f64,
            total as f64,
            self.fraction(total, visible),
            least,
        )
    }

    /// The thumb's start dragged to `start` along the track.
    pub fn drag_thumb(&mut self, start: f32, track: f32, total: u64, visible: u64, least: f32) {
        let fraction = self.thumb(track, total, visible, least).fraction_at(start);
        self.set_fraction(fraction, total, visible);
    }
}

/// Smooth scrolling for discrete input (a wheel's notches): the distance
/// still to scroll, eased out over about its duration. A new notch adds
/// to what is left, so a fast flick stays one continuous motion. A
/// duration of zero scrolls at once. Continuous input (touchpads) does
/// not go through it.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SmoothScroll {
    remaining: f64,
}

impl SmoothScroll {
    /// `dy` more pixels to scroll (down when positive).
    pub fn add(&mut self, dy: f64) {
        self.remaining += dy;
    }

    /// Stops: an instant jump (a scrollbar drag, go to) takes over.
    pub fn stop(&mut self) {
        self.remaining = 0.0;
    }

    /// Whether there is still distance to scroll.
    pub fn is_moving(&self) -> bool {
        self.remaining != 0.0
    }

    /// The pixels to scroll in a frame `dt` after the last, for a notch
    /// taking `duration`: exponential ease-out (a fifth of the duration
    /// per e-fold), the rest at once below half a pixel.
    pub fn step(&mut self, dt: Duration, duration: Duration) -> f64 {
        if self.remaining == 0.0 {
            return 0.0;
        }
        let total = duration.as_secs_f64();
        if total == 0.0 {
            return std::mem::take(&mut self.remaining);
        }
        let tau = total / 5.0;
        let dt = dt.as_secs_f64().clamp(0.0, total);
        let mut step = self.remaining * (1.0 - (-dt / tau).exp());
        if (self.remaining - step).abs() < 0.5 {
            step = self.remaining;
        }
        self.remaining -= step;
        step
    }
}

/// What a wheel or touchpad gave.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Wheel {
    /// A wheel's notches, in lines (three a notch), up when positive.
    Lines(f32),
    /// A touchpad's pixels, up when positive.
    Pixels(f32),
}

/// A scrolled viewport: where it is ([`ScrollAnchor`]) and the wheel's
/// distance still to go ([`SmoothScroll`]). A notch eases over the
/// configured duration, a touchpad's pixels apply at once, a key moves at
/// once ([`Scroller::reveal`] stops the easing first).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Scroller {
    /// Where it is.
    pub anchor: ScrollAnchor,
    /// The wheel's distance still to go.
    pub smooth: SmoothScroll,
}

impl Scroller {
    /// Takes `wheel` over `total` lines of `row` pixels, `visible` of them
    /// shown.
    pub fn wheel(&mut self, wheel: Wheel, row: f32, total: u64, visible: u64) {
        match wheel {
            Wheel::Lines(lines) => self.smooth.add(-f64::from(lines) * f64::from(row)),
            Wheel::Pixels(pixels) => {
                self.anchor
                    .scroll_by(-f64::from(pixels), row, total, visible);
            }
        }
    }

    /// One frame `dt` after the last, a notch taking `duration`; whether it
    /// still moves (it stops early at either end).
    pub fn frame(
        &mut self,
        dt: Duration,
        duration: Duration,
        row: f32,
        total: u64,
        visible: u64,
    ) -> bool {
        let dy = self.smooth.step(dt, duration);
        if dy != 0.0 {
            let before = self.anchor;
            self.anchor.scroll_by(dy, row, total, visible);
            if self.anchor == before {
                self.smooth.stop();
            }
        }
        self.smooth.is_moving()
    }

    /// Scrolled at once so `line` is visible ([`ScrollAnchor::reveal`]).
    pub fn reveal(&mut self, line: u64, total: u64, visible: u64, margin: u64) {
        self.smooth.stop();
        self.anchor.reveal(line, total, visible, margin);
    }

    /// Back at the top, at once.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// The pixels the content is scrolled up by, for a surface scrolled by
    /// pixels (each pixel a line).
    #[expect(clippy::cast_precision_loss, reason = "a panel's pixels")]
    pub fn pixels(&self) -> f32 {
        self.anchor.line as f32 + self.anchor.offset
    }
}

/// A code view's sideways scrolling: how far its text is scrolled left,
/// the widest of its lines in view and the width the text is shown in
/// (both as last drawn), and the cursor's place last brought into view.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Sideways {
    /// How far the text is scrolled left (pixels).
    pub x: f32,
    /// The widest line in view, from the text's left edge (pixels).
    pub content: f32,
    /// The width the text is shown in (pixels).
    pub view: f32,
    /// The cursor's place last brought into view.
    followed: Option<(u64, u64)>,
}

impl Sideways {
    /// How far the text scrolls: its widest line's overflow.
    pub fn max(&self) -> f32 {
        (self.content - self.view).max(0.0)
    }

    /// Whether it is scrolled or a line overflows (a scrollbar shows).
    pub fn scrolls(&self) -> bool {
        self.x > 0.0 || self.max() > 0.0
    }

    /// Scrolled by `dx` pixels (right when positive), within the widest
    /// line in view; lines narrower now than when it scrolled keep it
    /// where it is until it is scrolled back.
    pub fn scroll_by(&mut self, dx: f32) {
        self.x = (self.x + dx).min(self.max().max(self.x)).max(0.0);
    }

    /// Where it is, from 0 (left) to 1 (right), for a scrollbar.
    pub fn fraction(&self) -> f32 {
        let end = self.max().max(self.x);
        if end > 0.0 { self.x / end } else { 0.0 }
    }

    /// Its scrollbar's thumb on a track as wide as the view.
    pub fn thumb(&self, least: f32) -> Thumb {
        let extent = self.view + self.max().max(self.x);
        Thumb::new(
            self.view,
            f64::from(self.view),
            f64::from(extent),
            f64::from(self.fraction()),
            least,
        )
    }

    /// The thumb's left edge dragged to `left` along the track.
    #[expect(clippy::cast_possible_truncation, reason = "a scrollbar's pixels")]
    pub fn drag_thumb(&mut self, left: f32, least: f32) {
        self.x = self.thumb(least).fraction_at(left) as f32 * self.max();
    }

    /// A view's width further right (`right`) or left (a click on the
    /// track beside the thumb).
    pub fn page(&mut self, right: bool) {
        self.scroll_by(if right { self.view } else { -self.view });
    }

    /// The cursor at `at`, its band `left..right` (pixels from the text's
    /// left edge): brought into view if it moved since last; a scroll
    /// away from a cursor that stays is kept.
    pub fn follow(&mut self, at: (u64, u64), (left, right): (f32, f32)) {
        if self.followed == Some(at) || self.view <= 0.0 {
            return;
        }
        self.followed = Some(at);
        if left < self.x {
            self.x = left.max(0.0);
        } else if right > self.x + self.view {
            self.x = (right - self.view).min(left.max(0.0));
        }
    }
}

/// A scrollbar's thumb along its track (pixels): the view's share of the
/// content, at least `least` long, placed at the scroll's fraction. Its
/// drag moves the content its length over the track's per pixel, from
/// where it was taken.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Thumb {
    /// Where it starts along the track.
    pub start: f32,
    /// How long it is.
    pub len: f32,
    /// How long the track is.
    track: f32,
}

/// Where a press on a scrollbar's track fell.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Press {
    /// Before the thumb: a page back.
    Before,
    /// On the thumb, this far into it: a drag.
    On(f32),
    /// After the thumb: a page on.
    After,
}

impl Thumb {
    /// The thumb of a `track` pixels long showing `shown` of `total`, at
    /// `fraction` (0 at the start, 1 at the end).
    #[expect(clippy::cast_possible_truncation, reason = "a scrollbar's pixels")]
    pub fn new(track: f32, shown: f64, total: f64, fraction: f64, least: f32) -> Self {
        let track = track.max(0.0);
        let share = if total > 0.0 {
            (shown / total).clamp(0.0, 1.0) as f32
        } else {
            1.0
        };
        let len = (track * share).max(least).min(track);
        Self {
            start: fraction.clamp(0.0, 1.0) as f32 * (track - len),
            len,
            track,
        }
    }

    /// Where a press `at` pixels along the track fell.
    pub fn press(&self, at: f32) -> Press {
        if at < self.start {
            Press::Before
        } else if at >= self.start + self.len {
            Press::After
        } else {
            Press::On(at - self.start)
        }
    }

    /// The fraction the thumb stands for, started at `start` (a drag).
    pub fn fraction_at(&self, start: f32) -> f64 {
        let room = self.track - self.len;
        if room > 0.0 {
            f64::from((start / room).clamp(0.0, 1.0))
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Press, ScrollAnchor, Scroller, Sideways, SmoothScroll, Thumb, Wheel};

    const NOTCH: Duration = Duration::from_millis(120);

    #[test]
    fn sideways_stays_in_the_lines_and_follows_a_moving_cursor() {
        let mut s = Sideways {
            content: 1000.0,
            view: 400.0,
            ..Sideways::default()
        };
        s.scroll_by(-50.0);
        assert!(s.x.abs() < 1e-6);
        s.scroll_by(900.0);
        assert!((s.x - 600.0).abs() < 1e-6);
        assert!((s.fraction() - 1.0).abs() < 1e-6);
        // Narrower lines now: kept, until scrolled back.
        s.content = 500.0;
        s.scroll_by(10.0);
        assert!((s.x - 600.0).abs() < 1e-6);
        s.scroll_by(-550.0);
        assert!((s.x - 50.0).abs() < 1e-6);
        // The cursor right of the view: its band's end at the right edge.
        s.follow((3, 70), (700.0, 720.0));
        assert!((s.x - 320.0).abs() < 1e-6);
        // Scrolled away from it, the cursor unmoved: kept.
        s.scroll_by(-300.0);
        s.follow((3, 70), (700.0, 720.0));
        assert!((s.x - 20.0).abs() < 1e-6);
        // At the line's start again.
        s.follow((4, 0), (0.0, 20.0));
        assert!(s.x.abs() < 1e-6);
    }

    /// The thumb is the view's share of the track; dragged, the text
    /// moves the text's width over the track's per pixel, the thumb's end
    /// at the track's end the line's end; the track beside it pages.
    #[test]
    fn sideways_thumb_drags_one_to_one_and_the_track_pages() {
        let mut s = Sideways {
            content: 1000.0,
            view: 400.0,
            ..Sideways::default()
        };
        let thumb = s.thumb(20.0);
        assert!(thumb.start.abs() < 1e-6 && (thumb.len - 160.0).abs() < 1e-3);
        // 24 pixels of the thumb: 60 of the text.
        s.drag_thumb(24.0, 20.0);
        assert!((s.x - 60.0).abs() < 1e-3);
        assert!((s.thumb(20.0).start - 24.0).abs() < 1e-3);
        s.drag_thumb(240.0, 20.0);
        assert!((s.x - 600.0).abs() < 1e-3);
        s.drag_thumb(500.0, 20.0);
        assert!((s.x - 600.0).abs() < 1e-3);
        s.page(false);
        assert!((s.x - 200.0).abs() < 1e-3);
        s.page(false);
        assert!(s.x.abs() < 1e-6);
        s.page(true);
        assert!((s.x - 400.0).abs() < 1e-3);
    }

    /// 20 of 100 lines on a 400 px track: an 80 px thumb; a press on it
    /// keeps the grab point and a pixel of the thumb is a quarter line;
    /// beside it a page that way, to the end at most.
    #[test]
    fn line_thumb_drags_from_the_grab_point_and_the_track_pages() {
        let mut a = ScrollAnchor::default();
        let thumb = |a: &ScrollAnchor| a.thumb(400.0, 100, 20, 30.0);
        assert!((thumb(&a).len - 80.0).abs() < 1e-3);
        assert_eq!(thumb(&a).press(10.0), Press::On(10.0));
        assert_eq!(thumb(&a).press(80.0), Press::After);
        // Taken 10 px in, the pointer moved 32 px: the thumb's start too.
        a.drag_thumb(42.0 - 10.0, 400.0, 100, 20, 30.0);
        assert_eq!(a.line, 8);
        assert!((thumb(&a).start - 32.0).abs() < 1e-3);
        assert_eq!(thumb(&a).press(20.0), Press::Before);
        a.page(false, 100, 20);
        assert_eq!(a.line, 0);
        a.page(true, 100, 20);
        a.page(true, 100, 20);
        a.page(true, 100, 20);
        a.page(true, 100, 20);
        assert_eq!(a.line, 80);
        // A short thumb kept at its least length: the drag still ends at
        // the track's end.
        let short = Thumb::new(400.0, 20.0, 10_000.0, 0.0, 30.0);
        assert!((short.len - 30.0).abs() < 1e-3);
        assert!((short.fraction_at(370.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn smooth_scroll_eases_out_retargets_and_finishes() {
        let mut s = SmoothScroll::default();
        s.add(54.0);
        let frame = Duration::from_micros(16_667);
        let steps: Vec<f64> = (0..12).map(|_| s.step(frame, NOTCH)).collect();
        assert!(steps.windows(2).all(|w| w[1] <= w[0]), "{steps:?}");
        assert!(steps[0] < 54.0 * 0.6, "{steps:?}");
        // Done within about 120 ms (7 frames at 60 Hz), nothing lost.
        assert!(steps[7..].iter().all(|&d| d == 0.0), "{steps:?}");
        assert!((steps.iter().sum::<f64>() - 54.0).abs() < 1e-9);
        // A notch mid-animation adds to what is left, without a jump.
        s.add(54.0);
        let _ = s.step(frame, NOTCH);
        s.add(54.0);
        let second = s.step(frame, NOTCH);
        assert!(second > 0.0 && second < 54.0, "{second}");
    }

    #[test]
    fn zero_duration_scrolls_at_once() {
        let mut s = SmoothScroll::default();
        s.add(-60.0);
        assert!((s.step(Duration::from_millis(1), Duration::ZERO) + 60.0).abs() < 1e-9);
        assert!(!s.is_moving());
    }

    #[test]
    fn exact_past_f32_precision() {
        let total = 50_000_000;
        let mut a = ScrollAnchor {
            line: 40_000_000,
            offset: 0.0,
        };
        for _ in 0..1000 {
            a.scroll_by(1.0, 18.0, total, 40);
        }
        assert_eq!(a.line, 40_000_055);
        assert!((a.offset - 10.0).abs() < 1e-3, "{}", a.offset);
        a.scroll_by(-10.0 - 18.0 * 55.0, 18.0, total, 40);
        assert_eq!(a.line, 40_000_000);
        assert!(a.offset.abs() < 1e-3);
    }

    #[test]
    fn clamps_at_both_ends() {
        let mut a = ScrollAnchor::default();
        a.scroll_by(-100.0, 18.0, 1000, 40);
        assert_eq!(a, ScrollAnchor::default());
        a.scroll_by(1e12, 18.0, 1000, 40);
        assert_eq!(
            a,
            ScrollAnchor {
                line: 960,
                offset: 0.0
            }
        );
        a.scroll_by(-9.0, 18.0, 1000, 40);
        assert_eq!(a.line, 959);
        assert!((a.offset - 9.0).abs() < 1e-3);
    }

    #[test]
    fn reveal_keeps_a_margin_and_leaves_visible_lines_alone() {
        let mut a = ScrollAnchor {
            line: 100,
            offset: 0.0,
        };
        a.reveal(120, 1000, 40, 2);
        assert_eq!(a.line, 100);
        a.reveal(139, 1000, 40, 2);
        // Two lines below it stay visible: the last row is 142.
        assert_eq!(a.line, 103);
        a.reveal(50, 1000, 40, 2);
        assert_eq!(a.line, 48);
    }

    #[test]
    fn a_notch_eases_over_frames_and_stops_at_the_end() {
        let frame = Duration::from_micros(16_667);
        #[expect(clippy::cast_precision_loss, reason = "a few rows")]
        let at = |s: &Scroller| s.anchor.line as f32 * 22.0 + s.anchor.offset;
        // A tree of 22-pixel rows: a notch is three rows, 66 pixels.
        let mut s = Scroller::default();
        s.wheel(Wheel::Lines(-3.0), 22.0, 100, 20);
        let mut seen = vec![at(&s)];
        while s.frame(frame, NOTCH, 22.0, 100, 20) {
            seen.push(at(&s));
        }
        seen.push(at(&s));
        let moves: Vec<f32> = seen.windows(2).map(|w| w[1] - w[0]).collect();
        assert!((seen.last().unwrap() - 66.0).abs() < 1e-3, "{seen:?}");
        assert!(moves.len() >= 4, "{moves:?}");
        assert!(moves.iter().all(|&m| m < 66.0 * 0.6), "{moves:?}");
        // Past the end it stops, rather than easing into the wall.
        s.wheel(Wheel::Lines(-300.0), 22.0, 100, 20);
        let mut frames = 0;
        while s.frame(frame, NOTCH, 22.0, 100, 20) {
            frames += 1;
        }
        assert_eq!(s.anchor.line, 80);
        assert!(frames < 30, "{frames}");
        // A touchpad's pixels move at once; a key's reveal stops the easing.
        s.wheel(Wheel::Pixels(30.0), 22.0, 100, 20);
        assert!((at(&s) - (80.0 * 22.0 - 30.0)).abs() < 1e-3);
        s.wheel(Wheel::Lines(3.0), 22.0, 100, 20);
        s.reveal(10, 100, 20, 0);
        assert!(!s.frame(frame, NOTCH, 22.0, 100, 20));
        assert_eq!(s.anchor.line, 10);
    }
}
