//! The listing's branch-arrow gutter: each jump
//! of the function with an end on screen or spanning it, in the lane the
//! listing fixed for it ([`Arrow::lane`]: the shortest innermost, never
//! re-packed as the view scrolls). An arrow takes its lane's colour from
//! the theme's arrow palette (cycled, so neighbouring lanes differ), with a
//! dot at its source and an arrowhead at its target; a conditional jump is
//! dashed, an unconditional one solid, a backward one (a loop)
//! thicker. The arrows with an end on the cursor's line, and the one under
//! the pointer, are at full strength, the rest dimmed. The gutter has a
//! fixed number of lanes (`listing.arrow_lanes`); an arrow past them, or
//! one crossing another function (to its function's distant part, whose
//! lanes are not this one's), is a stub at each end naming the other end,
//! never a stack of lines in one lane, so a frame draws at most a lane's
//! height of dashes per lane.

use binbun_gui_view::listing::Arrow;
use gpui_kit::prelude::*;
use gpui_kit::{AnyElement, Bounds, canvas, fill, point, px, size};

use crate::listing_view::column;
use crate::theme::{hsla, with_alpha};
use crate::workspace::f;

/// Lanes this far apart, and the gap between the gutter and the text
/// (logical pixels).
pub const LANE: f32 = 7.0;
pub const GAP: f32 = 6.0;
/// The least room left of a stub's line for its label, and the line.
const LABEL_ROOM: f32 = 48.0;
const STUB: f32 = 8.0;
/// The stubs' labels' size, relative to the code font.
pub const LABEL_SCALE: f32 = 0.85;
/// A conditional jump's dashes.
const DASH: f32 = 3.0;
const DASH_GAP: f32 = 2.0;
/// The alpha of the arrows not at full strength: a thin line fades more
/// on a light editor, so a light theme dims less.
pub fn dim(dark: bool) -> u8 {
    if dark { 0x73 } else { 0x99 }
}

/// The gutter's width for `lanes` lanes (logical pixels): the lanes, at
/// least the room of a stub and its label, the gap, the arrowheads.
pub fn width(lanes: u32) -> f32 {
    let lanes = f32::from(u16::try_from(lanes).unwrap_or(u16::MAX));
    (LANE * lanes).max(LABEL_ROOM + STUB) + GAP + 4.0
}

/// What kind of jump an arrow is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kind {
    /// A conditional branch (dashed); else an unconditional jump (solid).
    pub conditional: bool,
    /// Its target is at or above it: a loop (thicker).
    pub backward: bool,
}

impl Kind {
    /// The kind of `arrow`.
    pub fn of(arrow: &Arrow) -> Self {
        Self {
            conditional: arrow.conditional,
            backward: arrow.to <= arrow.from,
        }
    }

    /// Its line's width.
    fn width(self) -> f32 {
        if self.backward { 2.0 } else { 1.0 }
    }
}

/// The lane `arrow` is drawn in among `lanes`, or `None` for a stub at
/// each end: past the lanes, or crossing another function.
pub fn lane_of(arrow: &Arrow, lanes: usize) -> Option<usize> {
    let k = usize::from(arrow.lane);
    (k < lanes && !arrow.crosses).then_some(k)
}

/// Lane `lane`'s colour: `palette` cycled.
pub fn colour(palette: &[u32; 8], lane: u16) -> u32 {
    palette
        .get(usize::from(lane) % palette.len())
        .copied()
        .unwrap_or_default()
}

/// Where a click on the arrow from `from` to `to` (addresses) goes: the
/// end not on the cursor's item, else (neither end, or both) its target.
pub fn other_end(from: u64, to: u64, cursor: Option<u64>) -> u64 {
    if cursor == Some(to) && from != to {
        from
    } else {
        to
    }
}

/// An end of an arrow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// The jump.
    Source,
    /// Its target.
    Target,
}

/// A stub's label at `end`, naming the other end (`name`, else its
/// `address`) in at most `room` columns ([`columns`]): `→loc_1E745` at the
/// source, `← from 1E6A3` at the target, else shorter forms, at worst the
/// address's last digits (what tells a function's lines apart).
pub fn stub_label(end: End, name: Option<&str>, address: u64, room: usize) -> String {
    let hex = format!("{address:X}");
    let (glyph, full) = match end {
        End::Source => ('→', name.map(|n| format!("→{n}"))),
        End::Target => ('←', Some(format!("← from {hex}"))),
    };
    let fits = full
        .into_iter()
        .chain([format!("{glyph}{hex}")])
        .find(|form| columns(form) <= room);
    fits.unwrap_or_else(|| {
        let keep = room.saturating_sub(3);
        let tail = hex
            .get(hex.len().saturating_sub(keep)..)
            .unwrap_or_default();
        if tail.is_empty() {
            glyph.to_string()
        } else {
            format!("{glyph}…{tail}")
        }
    })
}

/// The code font's columns `label` takes: an arrow glyph two (it comes
/// wide, from a fallback font), any other character one.
pub fn columns(label: &str) -> usize {
    label
        .chars()
        .map(|c| if matches!(c, '→' | '←') { 2 } else { 1 })
        .sum()
}

/// Where the gutter's pieces go in a frame (pixels, relative to it).
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    /// The gutter's width.
    pub width: f32,
    /// The distance between lanes.
    pub lane: f32,
    /// The gap to the text.
    pub gap: f32,
    /// How many lanes (`listing.arrow_lanes`).
    pub lanes: usize,
    /// A row's height.
    pub row: f32,
    /// The rows' height on screen.
    pub height: f32,
    /// The first line on screen.
    pub first: u64,
    /// How far it is scrolled up.
    pub offset: f32,
    /// A label character's width.
    pub label_char: f32,
}

impl Geometry {
    /// Lane `k`'s x.
    fn x(&self, k: usize) -> f32 {
        self.width - self.gap - 4.0 - f(k as u64) * self.lane
    }

    /// Where the arrowheads and dots end, by the text.
    fn tip(&self) -> f32 {
        self.width - 2.0
    }

    /// The middle of `line`, on screen or not: an end off screen keeps its
    /// true place, so a run reaching it moves with the view.
    fn y(&self, line: u64) -> f32 {
        let rows_away = if line >= self.first {
            f(line - self.first)
        } else {
            -f(self.first - line)
        };
        rows_away * self.row - self.offset + self.row / 2.0
    }

    fn visible(&self, y: f32) -> bool {
        y > 0.0 && y < self.height
    }

    /// How far the content is scrolled past a multiple of the dashes'
    /// period, so they keep their place in it.
    fn phase(&self) -> f32 {
        let scrolled = f64::from(self.row)
            * f64::from(u32::try_from(self.first).unwrap_or(u32::MAX))
            + f64::from(self.offset);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a remainder below the dash period"
        )]
        let phase = scrolled.rem_euclid(f64::from(DASH + DASH_GAP)) as f32;
        phase
    }
}

/// A filled rectangle of the gutter, relative to it; a circle if `round`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Quad {
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    color: u32,
    round: bool,
}

/// How an arrow is drawn.
#[derive(Clone, Copy, Debug)]
struct Pen {
    color: u32,
    width: f32,
    dashed: bool,
}

/// A region of the gutter standing for an arrow, for the pointer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Hit {
    left: f32,
    top: f32,
    right: f32,
    bottom: f32,
    /// The arrow's lines.
    pub from: u64,
    pub to: u64,
}

/// The arrow (its lines) under `(x, y)`: a stub first, then a lane's run,
/// then an end's line, the innermost first.
pub fn hit_at(hits: &[Hit], x: f32, y: f32) -> Option<(u64, u64)> {
    hits.iter()
        .find(|h| (h.left..h.right).contains(&x) && (h.top..h.bottom).contains(&y))
        .map(|h| (h.from, h.to))
}

/// A stub's label: its text right-aligned at `right`, on the row whose
/// middle is `y`.
#[derive(Clone, Debug, PartialEq)]
pub struct Label {
    pub text: String,
    pub right: f32,
    pub y: f32,
    pub color: u32,
}

/// A frame's gutter.
#[derive(Debug, Default)]
pub struct Drawn {
    /// The quads, those at full strength last.
    pub quads: Vec<Quad>,
    /// The stubs' labels, those at full strength last.
    pub labels: Vec<Label>,
    /// The arrows' regions, in [`hit_at`]'s order.
    pub hits: Vec<Hit>,
}

/// The gutter of `arrows`: `on` says which are at full strength, `label`
/// writes a stub's label at an end ([`stub_label`]) in some columns; the
/// others have alpha `dim` (their stubs' labels halfway to opaque: text
/// needs more than a line to stay legible).
pub fn lay_out(
    g: &Geometry,
    arrows: &[Arrow],
    palette: &[u32; 8],
    dim: u8,
    on: impl Fn(&Arrow) -> bool,
    label: impl Fn(&Arrow, End, usize) -> String,
) -> Drawn {
    let dim_label = dim + (0xff - dim) / 2;
    let mut faint = Drawn::default();
    let mut lit = Drawn::default();
    let mut runs = Vec::new();
    let mut ends: Vec<(usize, Hit)> = Vec::new();
    for arrow in arrows {
        let on = on(arrow);
        let kind = Kind::of(arrow);
        let color = colour(palette, arrow.lane);
        let pen = Pen {
            color: if on { color } else { with_alpha(color, dim) },
            width: kind.width(),
            dashed: kind.conditional,
        };
        let out = if on { &mut lit } else { &mut faint };
        if let Some(k) = lane_of(arrow, g.lanes) {
            let x = g.x(k);
            draw_arrow(&mut out.quads, g, pen, x, (g.y(arrow.from), g.y(arrow.to)));
            let half = g.lane / 2.0;
            let hit = |top: f32, bottom: f32, right: f32| Hit {
                left: x - half,
                top,
                right,
                bottom,
                from: arrow.from,
                to: arrow.to,
            };
            let (y_from, y_to) = (g.y(arrow.from), g.y(arrow.to));
            let (top, bottom) = (y_from.min(y_to).max(0.0), y_from.max(y_to).min(g.height));
            if bottom > top {
                runs.push(hit(top, bottom, x + half));
            }
            for y in [y_from, y_to].into_iter().filter(|&y| g.visible(y)) {
                ends.push((k, hit(y - g.row / 2.0, y + g.row / 2.0, g.width)));
            }
        } else {
            let label_color = if on {
                color
            } else {
                with_alpha(color, dim_label)
            };
            for (end, line) in [(End::Source, arrow.from), (End::Target, arrow.to)] {
                let y = g.y(line);
                if !g.visible(y) {
                    continue;
                }
                draw_stub(&mut out.quads, g, pen, y, end);
                let right = g.tip() - STUB - 2.0;
                // Less its padding.
                let text = label(arrow, end, column(right - 4.0, g.label_char));
                let w = f(columns(&text) as u64) * g.label_char + 4.0;
                out.hits.push(Hit {
                    left: right - w,
                    top: y - g.row / 2.0,
                    right: g.width,
                    bottom: y + g.row / 2.0,
                    from: arrow.from,
                    to: arrow.to,
                });
                out.labels.push(Label {
                    text,
                    right,
                    y,
                    color: label_color,
                });
            }
        }
    }
    ends.sort_by_key(|&(k, _)| k);
    faint.quads.append(&mut lit.quads);
    faint.labels.append(&mut lit.labels);
    faint.hits.append(&mut lit.hits);
    faint.hits.append(&mut runs);
    faint.hits.extend(ends.into_iter().map(|(_, hit)| hit));
    faint
}

/// The quads painted, filling the gutter.
pub fn paint(quads: Vec<Quad>) -> AnyElement {
    canvas(
        |_, _, _| {},
        move |bounds, (), window, _| {
            for q in &quads {
                let at = Bounds::new(
                    point(bounds.origin.x + px(q.x), bounds.origin.y + px(q.y)),
                    size(px(q.w), px(q.h)),
                );
                let quad = fill(at, hsla(q.color));
                window.paint_quad(if q.round {
                    quad.corner_radii(px(q.w / 2.0))
                } else {
                    quad
                });
            }
        },
    )
    .absolute()
    .size_full()
    .into_any_element()
}

/// One arrow in the lane at `x`: the run between its ends at `y_from` and
/// `y_to` (cut to the view), a line from each end on screen to the tip,
/// a dot at the source and an arrowhead at the target.
fn draw_arrow(out: &mut Vec<Quad>, g: &Geometry, pen: Pen, x: f32, (y_from, y_to): (f32, f32)) {
    let (top, bottom) = (y_from.min(y_to), y_from.max(y_to));
    let half = pen.width / 2.0;
    if pen.dashed {
        dashes(top, bottom, g.phase(), g.height, |y, len| {
            out.push(Quad {
                x: x - half,
                y,
                w: pen.width,
                h: len,
                color: pen.color,
                round: false,
            });
        });
    } else {
        let (start, end) = (top.max(-pen.width), bottom.min(g.height + pen.width));
        if end > start {
            segment(out, pen, x, start - half, end - start + pen.width, false);
        }
    }
    let tip = g.tip();
    if g.visible(y_from) {
        let d = dot(pen);
        segment(out, pen, x - half, y_from, tip - d - x + half, true);
        push_dot(out, pen, tip, y_from);
    }
    if g.visible(y_to) {
        segment(out, pen, x - half, y_to, tip - 4.0 - x + half, true);
        arrowhead(out, pen, tip, y_to);
    }
}

/// A stub at `end`, on the row whose middle is `y`: a short solid line to
/// the tip, the dot or the arrowhead.
fn draw_stub(out: &mut Vec<Quad>, g: &Geometry, pen: Pen, y: f32, end: End) {
    let tip = g.tip();
    let pen = Pen {
        dashed: false,
        ..pen
    };
    let start = tip - STUB;
    match end {
        End::Source => {
            segment(out, pen, start, y, STUB - dot(pen), true);
            push_dot(out, pen, tip, y);
        }
        End::Target => {
            segment(out, pen, start, y, STUB - 4.0, true);
            arrowhead(out, pen, tip, y);
        }
    }
}

/// The source dot's diameter.
fn dot(pen: Pen) -> f32 {
    pen.width + 3.0
}

/// The source dot ending at `tip`, on the row whose middle is `y`.
fn push_dot(out: &mut Vec<Quad>, pen: Pen, tip: f32, y: f32) {
    let d = dot(pen);
    out.push(Quad {
        x: tip - d,
        y: y - d / 2.0,
        w: d,
        h: d,
        color: pen.color,
        round: true,
    });
}

/// An arrowhead pointing right at `tip`, on the row whose middle is `y`.
fn arrowhead(out: &mut Vec<Quad>, pen: Pen, tip: f32, y: f32) {
    let half = pen.width / 2.0;
    for i in 0..4u8 {
        let reach = f32::from(3 - i);
        out.push(Quad {
            x: tip - 4.0 + f32::from(i),
            y: y - reach - half,
            w: 1.0,
            h: 2.0 * reach + pen.width,
            color: pen.color,
            round: false,
        });
    }
}

/// The dashes of a run from `top` to `bottom` (on screen or off) inside
/// `height`, each as `(y, length)`: `DASH` long every `DASH + DASH_GAP`,
/// the first starting `phase` before a multiple of the period, so the
/// dashes keep their place as the content scrolls.
fn dashes(top: f32, bottom: f32, phase: f32, height: f32, mut each: impl FnMut(f32, f32)) {
    let period = DASH + DASH_GAP;
    let (top, bottom) = (top.max(0.0), bottom.min(height));
    if bottom <= top {
        return;
    }
    // The dash at or before `top`, on the content's grid.
    let mut at = top - (top + phase).rem_euclid(period);
    while at < bottom {
        let (from, to) = (at.max(top), (at + DASH).min(bottom));
        if to > from {
            each(from, to - from);
        }
        at += period;
    }
}

/// A line `len` long from `(x, y)`, right if `horizontal` else down.
fn segment(out: &mut Vec<Quad>, pen: Pen, x: f32, y: f32, len: f32, horizontal: bool) {
    let (step, gap) = if pen.dashed {
        (DASH, DASH_GAP)
    } else {
        (len.max(0.0), 0.0)
    };
    let half = pen.width / 2.0;
    let mut at = 0.0;
    while at < len {
        let n = step.min(len - at);
        out.push(if horizontal {
            Quad {
                x: x + at,
                y: y - half,
                w: n,
                h: pen.width,
                color: pen.color,
                round: false,
            }
        } else {
            Quad {
                x: x - half,
                y: y + at,
                w: pen.width,
                h: n,
                color: pen.color,
                round: false,
            }
        });
        at += step + gap;
        if step <= 0.0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use binbun_gui_view::listing::Arrow;

    use super::{
        DASH, DASH_GAP, End, Geometry, Kind, colour, dashes, hit_at, lay_out, other_end,
        stub_label, width,
    };
    /// Eight distinct colours: the lanes' palette in these tests (each
    /// theme's own is tested with the themes).
    const PALETTE: [u32; 8] = [
        0x1111_11ff,
        0x2222_22ff,
        0x3333_33ff,
        0x4444_44ff,
        0x5555_55ff,
        0x6666_66ff,
        0x7777_77ff,
        0x8888_88ff,
    ];

    /// A gutter of `lanes` lanes, 7 px apart, over 40 rows of 10 px from
    /// line 100.
    fn geometry(lanes: usize) -> Geometry {
        Geometry {
            width: width(u32::try_from(lanes).unwrap()),
            lane: 7.0,
            gap: 6.0,
            lanes,
            row: 10.0,
            height: 400.0,
            first: 100,
            offset: 0.0,
            label_char: 4.0,
        }
    }

    fn arrow(from: u64, to: u64, lane: u16) -> Arrow {
        Arrow {
            from,
            to,
            conditional: true,
            crosses: false,
            lane,
        }
    }

    fn label(arrow: &Arrow, end: End, room: usize) -> String {
        match end {
            End::Source => stub_label(end, Some("loc_1E745"), arrow.to, room),
            End::Target => stub_label(end, None, arrow.from, room),
        }
    }

    #[test]
    fn neighbouring_lanes_differ_in_colour() {
        for lane in 0..64u16 {
            assert_ne!(colour(&PALETTE, lane), colour(&PALETTE, lane + 1), "{lane}");
        }
        // Eight lanes in a row are eight colours.
        let mut first: Vec<u32> = (0..8).map(|k| colour(&PALETTE, k)).collect();
        first.sort_unstable();
        first.dedup();
        assert_eq!(first.len(), 8);
    }

    #[test]
    fn jumps_are_classified_by_condition_and_direction() {
        let kind = |from, to, conditional| {
            Kind::of(&Arrow {
                from,
                to,
                conditional,
                crosses: false,
                lane: 0,
            })
        };
        let k = |conditional, backward| Kind {
            conditional,
            backward,
        };
        assert_eq!(kind(10, 20, true), k(true, false));
        assert_eq!(kind(20, 10, false), k(false, true));
        // A jump to itself is a loop.
        assert_eq!(kind(15, 15, false), k(false, true));
    }

    #[test]
    fn a_click_goes_to_the_end_away_from_the_cursor() {
        assert_eq!(other_end(0x10, 0x40, Some(0x10)), 0x40);
        assert_eq!(other_end(0x10, 0x40, Some(0x40)), 0x10);
        assert_eq!(other_end(0x10, 0x40, Some(0x20)), 0x40);
        assert_eq!(other_end(0x10, 0x40, None), 0x40);
        assert_eq!(other_end(0x10, 0x10, Some(0x10)), 0x10);
    }

    #[test]
    fn arrows_past_the_lanes_become_labelled_stubs() {
        let g = geometry(4);
        // Twelve nested jumps with both ends on screen, in lanes 0 to 11,
        // and one in lane 0 crossing another function.
        let mut arrows: Vec<Arrow> = (0..12u16)
            .map(|k| arrow(120 - u64::from(k), 121 + u64::from(k), k))
            .collect();
        arrows.push(Arrow {
            crosses: true,
            ..arrow(135, 102, 0)
        });
        let drawn = lay_out(&g, &arrows, &PALETTE, 0x73, |_| false, label);
        // Nine stubs, two labels each, and no line left of the fourth lane.
        assert_eq!(drawn.labels.len(), 18);
        let outermost = g.x(3) - 1.0;
        assert!(drawn.quads.iter().all(|q| q.x >= outermost), "a fifth lane");
        let texts: Vec<&str> = drawn.labels.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts.first(), Some(&"→loc_1E745"));
        assert_eq!(texts.get(1), Some(&"← from 74"));
        // The crossing jump draws no line in lane 0 past its own ends.
        assert_eq!(hit_at(&drawn.hits, g.x(0), g.y(105)), None);
        assert_eq!(texts.get(17), Some(&"← from 87"));
        // Each stub's label is under the pointer for its arrow; the gutter
        // left of the lanes, off a stub's row, is not.
        let stub = drawn.labels.get(1).unwrap();
        assert_eq!(
            hit_at(&drawn.hits, stub.right - 2.0, stub.y),
            Some((116, 125))
        );
        assert_eq!(hit_at(&drawn.hits, 2.0, g.y(100)), None);
        // A lane's run is under the pointer for its arrow.
        assert_eq!(hit_at(&drawn.hits, g.x(2), g.y(120)), Some((118, 123)));
    }

    #[test]
    fn stub_labels_shorten_to_fit() {
        let source = |room| stub_label(End::Source, Some("loc_1E745"), 0x1_e745, room);
        // An arrow glyph takes two columns.
        assert_eq!(source(11), "→loc_1E745");
        assert_eq!(source(10), "→1E745");
        assert_eq!(source(7), "→1E745");
        assert_eq!(source(6), "→…745");
        assert_eq!(source(3), "→");
        let target = |room| stub_label(End::Target, None, 0x1_e6a3, room);
        assert_eq!(target(13), "← from 1E6A3");
        assert_eq!(target(12), "←1E6A3");
    }

    #[test]
    fn a_frame_draws_a_lanes_height_of_dashes_however_many_arrows_span_it() {
        let g = geometry(10);
        // Four hundred jumps spanning the view, ends off screen: past the
        // lanes they have no stub on screen, so they draw nothing.
        let arrows: Vec<Arrow> = (0..400u16)
            .map(|k| arrow(50 - u64::from(k % 50), 200 + u64::from(k), k))
            .collect();
        let drawn = lay_out(&g, &arrows, &PALETTE, 0x73, |_| false, label);
        // Ten lanes of 400 px at a dash every 5 px.
        assert!(drawn.quads.len() <= 10 * 80);
        assert_eq!(drawn.labels, []);
        assert!(drawn.quads.iter().all(|q| q.color & 0xff == 0x73));
    }

    #[test]
    fn dashes_move_with_the_content_and_stay_in_their_run() {
        let collect = |top, bottom, phase| {
            let mut out = Vec::new();
            dashes(top, bottom, phase, 600.0, |y, len| out.push((y, len)));
            out
        };
        // 600 px at a dash every 5 px; cut to the run and to the view.
        assert_eq!(collect(-500.0, 900.0, 0.0).len(), 120);
        assert_eq!(collect(0.0, 4.0, 0.0), [(0.0, 3.0)]);
        assert_eq!(collect(-50.0, -1.0, 0.0), []);
        // Scrolling one pixel moves every dash with the content.
        let scrolled = collect(0.0, 600.0, 1.0);
        assert_eq!(scrolled.get(1).map(|d| d.0), Some(DASH + DASH_GAP - 1.0));
        for pair in scrolled.windows(2) {
            assert!(pair[0].0 + pair[0].1 <= pair[1].0);
        }
    }
}
