//! A listing pane: the listing's lines drawn in rows,
//! the branch-arrow gutter, the function under the cursor as a lit area
//! (a lighter background and a 2 px edge band), the C statements' tints
//! on their instructions' addresses, the links a hovered C token makes,
//! long hex numbers in two tones per 4-digit group, and the landing pulse.
//! A right click moves the cursor to the token and opens its context menu.
//! Ctrl+click or a middle click on a name opens what it names in a new
//! tab (with Shift, behind the active one).
//! A drag selects whole lines (Shift+click and Shift with the keys extend
//! from the cursor; a plain click or Escape drops them), washed in the
//! selection's colour over the others' selections in their colours; a
//! synced listing washes the instructions behind the C's cursor line or
//! selection.
//! The comment field opens in place at the comment column of its item's
//! first line, the item's comment lines giving way to it.

use std::ops::Range;
use std::rc::Rc;
use std::sync::Arc;

use binbun::Database;
use binbun_gui_view::cdoc::CDocument;
use binbun_gui_view::context::Surface;
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::listing::{Arrow, LineKind, Listing, Overlay, Role, Token};
use binbun_gui_view::scroll::{Press, Scroller};
use binbun_gui_view::talk::listing_marks;
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, ElementId, KeyDownEvent, MouseButton, MouseDownEvent, MouseMoveEvent,
    ScrollEvent, StyledText, TextRun, Window, div, px,
};

use crate::arrows::{self, End, GAP, Geometry, Hit, LABEL_SCALE, LANE};
use crate::collab::{TickStyle, caret_bar, caret_wash, selection_wash, token_column};
use crate::highlight::Highlight;
use crate::panes::measured;
use crate::scrolling::{scrolled, wheel};
use crate::search_view::{FindKind, marked};
use crate::tabs::name_click;
use crate::theme::{dim, hsla};
use crate::workspace::{Link, PULSE, TabKind, Workspace, f};

/// The scrollbar: 14 px and its 1 px track border.
pub const SCROLLBAR: f32 = 15.0;

impl Workspace {
    /// The arrow gutter's width, zoomed: fixed by `listing.arrow_lanes`.
    pub fn gutter_width(&self) -> f32 {
        self.row(arrows::width(self.settings.arrow_lanes))
    }

    /// The C document linked to the listing panes: the first synced pane
    /// showing C.
    pub fn linked_document(&self) -> Option<Arc<CDocument>> {
        self.layout
            .panes()
            .filter(|p| p.synced)
            .find_map(|p| self.document(p.tabs.get(p.active).map(|t| &t.content)?))
            .cloned()
    }

    /// Pane `id`'s listing.
    #[expect(clippy::too_many_lines, reason = "one row's layers, in order")]
    pub fn render_listing(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let row_h = self.row(self.settings.listing_line_height);
        let rows = self.rows(id, self.settings.listing_line_height);
        let focused = self.layout.focused() == id;
        let commenting = self.comment.as_ref().is_some_and(|c| c.pane == id);
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        let bounds = Rc::clone(&state.bounds);
        let mut pane = div()
            .id(("listing", id.0))
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
                    this.listing_down(id, e, window, cx);
                }),
            )
            .on_mouse_down(
                MouseButton::Middle,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.listing_down(id, e, window, cx);
                }),
            )
            .on_mouse_down(
                MouseButton::Right,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.listing_right(id, e, window, cx);
                }),
            )
            .on_mouse_move(cx.listener(move |this, e: &MouseMoveEvent, window, cx| {
                this.listing_move(id, e, window, cx);
            }))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |this, _, _, _| {
                    this.scrollbar_drag = None;
                    this.sideways_drag = None;
                    if let Some(state) = this.panes.get_mut(&id) {
                        state.listing.selection.release();
                    }
                }),
            )
            .on_key_down(cx.listener(move |this, e: &KeyDownEvent, _, cx| {
                if this.selection_key(id, e) {
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
        let (Some(listing), Some(session)) = (self.listing.clone(), self.session.as_ref()) else {
            return pane.into_any_element();
        };
        let Some(db) = session.database() else {
            return pane.into_any_element();
        };
        let overlay = session.overlay().clone();
        let cursor_address = listing.line(state.listing.cursor).map(|l| l.address);
        // The others' cursors in a shared session.
        let remote = self.listing_carets(&listing);
        let mut carets: Vec<AnyElement> = Vec::new();
        let mut own = None;
        // The lit area: the function under the cursor.
        let entry = cursor_address
            .and_then(|a| listing.function_of(a))
            .map(|(_, e)| e);
        let lit = match (&state.listing.lit, entry) {
            (Some((e, range)), Some(entry)) if *e == entry => Some(range.clone()),
            (_, Some(entry)) => {
                let range = listing.function_lines(entry);
                if let (Some(range), Some(state)) = (&range, self.panes.get_mut(&id)) {
                    state.listing.lit = Some((entry, range.clone()));
                }
                range
            }
            (_, None) => None,
        };
        // The text scrolled sideways, the cursor's token kept in view.
        let gutter = self.gutter_width();
        let char_w = self.char_width.unwrap_or(8.0);
        let view = self.sideways_view(id, gutter);
        let cursor_band = self.panes.get(&id).map(|s| {
            let (line, token) = (s.listing.cursor, s.listing.token);
            let tokens = listing.render(db, line, &overlay).tokens;
            let x = f(u64::from(token_column(&tokens, token))) * char_w;
            let place = token.map_or(u64::MAX, |t| t as u64);
            ((line, place), (x - 4.0 * char_w, x + 4.0 * char_w))
        });
        let sx = self.panes.get_mut(&id).map_or(0.0, |s| {
            let side = &mut s.listing.side;
            side.view = view;
            if let Some((at, band)) = cursor_band {
                side.follow(at, band);
            }
            side.x
        });
        let Some(state) = self.panes.get(&id) else {
            return pane.into_any_element();
        };
        let linked = self
            .layout
            .pane(id)
            .filter(|p| p.synced)
            .and_then(|_| self.linked_document())
            .filter(|d| entry == Some(d.entry));
        let hovered: &[u64] = match &self.link {
            Some(Link::C { addresses, .. }) => addresses,
            Some(Link::Listing(_)) | None => &[],
        };
        // The instructions behind the C's cursor line or selection.
        let behind = if linked.is_some() {
            self.behind_c()
        } else {
            Vec::new()
        };
        let selected = state.listing.selection.range(state.listing.cursor);
        let others_selected = self.listing_selections(&listing);
        let pulse = self
            .pulse
            .filter(|(p, _, at)| *p == id && at.elapsed() < PULSE);
        if pulse.is_some() {
            window.request_animation_frame();
        }
        let first = state.listing.scroll.anchor.line;
        let offset = state.listing.scroll.anchor.offset;
        // The comment field: its item's first line, the lines its comment
        // takes now, its column, the rows it takes.
        let field = self
            .comment
            .as_ref()
            .filter(|c| c.pane == id)
            .and_then(|c| {
                let n = listing.line_of(c.field.address);
                let (_, line, column) = listing.comment_place(db, n, &overlay)?;
                Some((c, line, listing.comment_lines(line), column))
            });
        // The rows below the field move by what it takes more than the
        // comment's lines.
        let grown = |n: u64| -> f32 {
            field
                .as_ref()
                .filter(|(_, _, lines, _)| n >= lines.end)
                .map_or(0.0, |(c, _, lines, _)| {
                    (f(c.field.lines() as u64) - f(lines.end - lines.start)) * row_h
                })
        };
        let freed = field.as_ref().map_or(0, |(c, _, lines, _)| {
            (lines.end - lines.start).saturating_sub(c.field.lines() as u64)
        });
        let end = first.saturating_add(rows + 1 + freed).min(listing.len());
        self.drawn_listing(&listing, first..end);
        let edge = self.row(2.0);
        let mut field_box = None;
        // The widest line drawn, from the text's left edge.
        let mut widest: f32 = 0.0;
        let bookmarks = self.bookmark_colors();
        let threads = listing_marks(&self.threads.all);
        for n in first..end {
            let Some(line) = listing.line(n) else {
                break;
            };
            if field
                .as_ref()
                .is_some_and(|(_, at, lines, _)| lines.contains(&n) && n != *at)
            {
                continue;
            }
            let mut rendered = listing.render(db, n, &overlay);
            if let Some((edit, _, _, column)) = field.as_ref().filter(|(_, at, ..)| *at == n) {
                // The line without its comment, then `; ` at the comment
                // column, where the field goes.
                if rendered
                    .tokens
                    .last()
                    .is_some_and(|t| t.role == Role::Comment)
                {
                    rendered
                        .tokens
                        .truncate(rendered.tokens.len().saturating_sub(2));
                }
                let width: usize = rendered.tokens.iter().map(|t| t.text.chars().count()).sum();
                rendered.tokens.push(Token {
                    text: " ".repeat(column.saturating_sub(width).max(1)),
                    role: Role::Space,
                    target: None,
                    automatic: false,
                });
                rendered.tokens.push(Token {
                    text: "; ".to_owned(),
                    role: Role::Comment,
                    target: None,
                    automatic: false,
                });
                let x = gutter + f(*column as u64 + 2) * char_w;
                let y = f(n - first) * row_h - offset;
                field_box = Some(self.comment_box(edit, x - sx, y, row_h));
            }
            let in_lit = lit.as_ref().is_some_and(|r| r.contains(&n));
            let mut background = if n == state.listing.cursor {
                Some(if focused {
                    theme.active_line
                } else {
                    theme.lit()
                })
            } else if hovered.binary_search(&line.address).is_ok()
                && line.kind == LineKind::Instruction
            {
                Some(theme.selection)
            } else if line.kind == LineKind::Instruction && self.origin_address(line.address) {
                Some(crate::theme::with_alpha(theme.accent, 0x30))
            } else if line.kind == LineKind::Instruction
                && behind.binary_search(&line.address).is_ok()
            {
                Some(theme.provenance())
            } else if in_lit {
                Some(theme.lit())
            } else {
                None
            };
            if let Some((_, at_line, at)) = pulse
                && at_line == n
            {
                let left = 1.0 - at.elapsed().as_secs_f32() / PULSE.as_secs_f32();
                let alpha = (left.clamp(0.0, 1.0)
                    * f32::from(u8::try_from(theme.active_match & 0xff).unwrap_or(0)))
                .round();
                background = Some(crate::theme::with_alpha(
                    theme.active_match,
                    alpha_u8(alpha),
                ));
            }
            let tint = linked
                .as_ref()
                .filter(|_| line.kind == LineKind::Instruction)
                .and_then(|d| d.tint_of(line.address))
                .map(|k| theme.tint(k));
            let mut text = String::new();
            let mut runs: Vec<TextRun> = Vec::with_capacity(rendered.tokens.len() + 4);
            for (i, t) in rendered.tokens.iter().enumerate() {
                if t.text.is_empty() {
                    continue;
                }
                text.push_str(&t.text);
                let lit_token = t.role != Role::Space
                    && state.listing.highlight.as_deref() == Some(t.text.as_str());
                let color = if t.role == Role::Prefix {
                    if cursor_address == Some(line.address) {
                        theme.accent
                    } else {
                        theme.prefix(line.item)
                    }
                } else {
                    theme.token(t)
                };
                let back = if lit_token {
                    Some(theme.search_match)
                } else if i == 0 {
                    tint
                } else {
                    None
                };
                for (len, tone) in tones(&t.text, matches!(t.role, Role::Prefix | Role::Number)) {
                    let c = if tone { dim(color) } else { color };
                    runs.push(self.text_run(len, c, back));
                }
            }
            let runs = marked(runs, &self.find_marks(id, &FindKind::Listing, n));
            let y = f(n - first) * row_h - offset + grown(n);
            let written = (line.kind == LineKind::Instruction)
                .then(|| self.run_registers(line.address))
                .flatten();
            // Under the text: the others' selections, then this one's.
            let washes: Vec<AnyElement> = others_selected
                .iter()
                .filter(|(lines, _)| lines.contains(&n))
                .map(|(_, color)| *color)
                .chain(
                    selected
                        .as_ref()
                        .filter(|lines| lines.contains(&n))
                        .map(|_| hsla(theme.selection)),
                )
                .map(|color| selection_wash(color, (0.0, None), row_h))
                .collect();
            let written_w = written.as_ref().map_or(0.0, |w: &String| {
                f32::from(self.z(16.0)) + f(w.chars().count() as u64) * char_w
            });
            widest = widest.max(f(text.chars().count() as u64 + 1) * char_w + written_w);
            let here: Vec<_> = remote.get(&n).into_iter().flatten().collect();
            // The text, laid out from the row's left edge past the arrows,
            // scrolls sideways; the gutter and its marks stay put.
            let body = div()
                .pl(px(gutter))
                .flex()
                .whitespace_nowrap()
                .child(StyledText::new(text).with_runs(runs))
                .when_some(written, |d, written| {
                    d.child(
                        div()
                            .flex_none()
                            .ml(self.z(16.0))
                            .text_color(hsla(theme.text_muted))
                            .child(written),
                    )
                })
                .when(!here.is_empty(), |d| {
                    d.child(self.line_badges(&here, row_h))
                });
            let mut row = div()
                .absolute()
                .top(px(y))
                .left_0()
                .right(self.z(SCROLLBAR))
                .h(px(row_h))
                .overflow_hidden()
                .when_some(background, |d, b| d.bg(hsla(b)))
                .children(washes)
                .child(scrolled(gutter, sx, body));
            if in_lit {
                row = row.child(
                    div()
                        .absolute()
                        .top_0()
                        .bottom_0()
                        .left(px(gutter - edge - char_w * 0.5))
                        .w(px(edge))
                        .bg(hsla(theme.lit_edge())),
                );
            }
            let content = matches!(line.kind, LineKind::Instruction | LineKind::Data);
            let colors = bookmarks.get(&line.address).filter(|_| content);
            if let Some(colors) = colors {
                row = row.children(self.bookmark_marks(colors, row_h, 0.0));
            }
            if content && let Some(mark) = threads.get(&line.address) {
                let bars = colors.map_or(0, |c| c.len().min(3));
                let x = f32::from(self.z(3.0 + 4.0 * f(bars as u64)));
                row = row.child(self.thread_mark(
                    ("listing-thread", usize::try_from(n).unwrap_or(usize::MAX)),
                    &mark.threads,
                    mark.resolved,
                    (x, row_h),
                    cx,
                ));
            }
            // A caret scrolled under the gutter is not drawn.
            let caret_at = |column: u32| {
                Some(gutter + f(u64::from(column)) * char_w - sx).filter(|&x| x >= gutter)
            };
            for caret in &here {
                row = row.child(caret_wash(caret, row_h));
                let column = caret
                    .column
                    .unwrap_or_else(|| token_column(&rendered.tokens, None));
                if let Some(x) = caret_at(column) {
                    carets.push(caret_bar(caret.color, (x, y, row_h)));
                }
            }
            // One's own caret at its token, where the others see it (not
            // while the comment field takes the typing).
            if n == state.listing.cursor && field.is_none() {
                let column = token_column(&rendered.tokens, state.listing.token);
                own = caret_at(column).map(|x| caret_bar(self.own_caret(focused), (x, y, row_h)));
            }
            pane = pane.child(row);
        }
        let (cursor, anchor) = (state.listing.cursor, state.listing.scroll.anchor);
        let (gutter_el, hits) = self.arrows(id, &listing, first..end, db, &overlay, cx);
        if let Some(state) = self.panes.get_mut(&id) {
            state.listing.arrow_hits = hits;
        }
        let sideways_bar = self.measured_sideways(id, gutter, widest);
        let total = listing.len();
        let h = self
            .panes
            .get(&id)
            .map_or(0.0, |s| f32::from(s.bounds.get().size.height));
        #[expect(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            reason = "a scrollbar's pixels"
        )]
        let ticks = self.person_ticks(
            id,
            h,
            true,
            TickStyle::Bar,
            {
                let listing = Arc::clone(&listing);
                move |cursor| {
                    (total > 0)
                        .then(|| (listing.line_of(cursor.address) as f64 / total as f64) as f32)
                }
            },
            cx,
        );
        pane.children(carets)
            .children(own)
            .child(gutter_el)
            .children(field_box)
            .child(self.scrollbar(id, total, cursor, anchor, rows))
            .children(sideways_bar)
            .children(ticks)
            .into_any_element()
    }

    /// A run of the code font.
    pub fn text_run(&self, len: usize, color: u32, background: Option<u32>) -> TextRun {
        TextRun {
            len,
            font: self.code_font(),
            color: hsla(color),
            background_color: background.map(hsla),
            underline: None,
            strikethrough: None,
        }
    }

    /// The scrollbar: 14 px, a 1 px track border, the thumb, and the
    /// cursor as a 2 px accent mark.
    pub fn scrollbar(
        &self,
        id: PaneId,
        total: u64,
        cursor: u64,
        anchor: binbun_gui_view::scroll::ScrollAnchor,
        rows: u64,
    ) -> AnyElement {
        let theme = self.theme;
        let h = self
            .panes
            .get(&id)
            .map_or(0.0, |s| f32::from(s.bounds.get().size.height));
        #[expect(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            reason = "a scrollbar's pixels"
        )]
        let ratio = |a: u64, b: u64| {
            if b == 0 {
                1.0
            } else {
                (a as f64 / b as f64) as f32
            }
        };
        let thumb = anchor.thumb(h, total, rows, self.row(22.0));
        let mark = (total > 0).then(|| ratio(cursor, total) * (h - 2.0));
        div()
            .absolute()
            .top_0()
            .bottom_0()
            .right_0()
            .w(self.z(SCROLLBAR))
            .border_l_1()
            .border_color(hsla(theme.scrollbar_track_border))
            .child(
                div()
                    .absolute()
                    .left_0()
                    .right_0()
                    .top(px(thumb.start))
                    .h(px(thumb.len))
                    .bg(hsla(theme.scrollbar_thumb)),
            )
            .when_some(mark, |d, y| {
                d.child(
                    div()
                        .absolute()
                        .left_0()
                        .right_0()
                        .top(px(y))
                        .h(px(2.0))
                        .bg(hsla(theme.accent)),
                )
            })
            .into_any_element()
    }

    /// Wheel scrolling in pane `id`: a wheel's notches eased (or at once
    /// with smooth scrolling off), a touchpad's pixels at once.
    pub fn wheel(&mut self, id: PaneId, e: &ScrollEvent, cx: &mut Context<Self>) {
        // Scrolling oneself stops following a participant.
        self.unfollow();
        let c = matches!(self.layout.active(id), Some(TabKind::C { .. }));
        let height = self.line_height(id);
        let row = self.row(height);
        self.wheel_sideways(id, e, row);
        if e.modifiers.shift {
            cx.notify();
            return;
        }
        let rows = self.rows(id, height);
        let unified = self.shows_unified(id);
        let total = if unified {
            self.panes
                .get(&id)
                .and_then(|s| s.unified.flat.as_ref())
                .map_or(0, |f| f.len() as u64)
        } else if c {
            self.layout
                .active(id)
                .and_then(|k| self.document(k))
                .map_or(0, |d| d.lines.len() as u64)
        } else {
            self.listing.as_ref().map_or(0, |l| l.len())
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let scroll = if unified {
            &mut state.unified.scroll
        } else if c {
            &mut state.c.scroll
        } else {
            // The arrow under the pointer moves away with the content.
            state.listing.arrow = None;
            &mut state.listing.scroll
        };
        scroll.wheel(wheel(e), row, total, rows);
        cx.notify();
    }

    /// The branch arrow (its lines) under `position` in pane `id`'s
    /// gutter, as last drawn.
    fn arrow_under(
        &self,
        id: PaneId,
        position: gpui_kit::Point<gpui_kit::Pixels>,
    ) -> Option<(u64, u64)> {
        let state = self.panes.get(&id)?;
        let b = state.bounds.get();
        let x = f32::from(position.x - b.origin.x);
        let y = f32::from(position.y - b.origin.y);
        arrows::hit_at(&state.listing.arrow_hits, x, y).filter(|_| x < self.gutter_width())
    }

    /// The line and column under `position` in pane `id`'s listing, and
    /// whether it is on the scrollbar.
    fn listing_hit(
        &self,
        id: PaneId,
        position: gpui_kit::Point<gpui_kit::Pixels>,
    ) -> Option<(u64, usize, bool)> {
        let state = self.panes.get(&id)?;
        let b = state.bounds.get();
        let x = f32::from(position.x - b.origin.x);
        let y = f32::from(position.y - b.origin.y);
        let on_bar = x > f32::from(b.size.width) - f32::from(self.z(SCROLLBAR));
        let row = self.row(self.settings.listing_line_height);
        let line = state.listing.scroll.anchor.line
            + crate::workspace::rows_in(y + state.listing.scroll.anchor.offset + 1.0, row)
            - 1;
        let text_x = (x - self.gutter_width()).max(0.0) + state.listing.side.x;
        let col = column(text_x, self.char_width.unwrap_or(8.0));
        Some((line, col, on_bar))
    }

    fn listing_down(
        &mut self,
        id: PaneId,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.close_peek();
        // A click elsewhere in the pane drops the comment field (a click
        // in it moves its caret).
        if self.comment.as_ref().is_some_and(|c| c.pane == id) {
            self.comment = None;
        }
        if self.sideways_down(id, e) {
            cx.notify();
            return;
        }
        let Some((line, col, on_bar)) = self.listing_hit(id, e.position) else {
            return;
        };
        if on_bar {
            if e.button != MouseButton::Left {
                return;
            }
            self.scrollbar_down(id, e.position.y);
            cx.notify();
            return;
        }
        if self.layout.focused() != id {
            self.focus_pane(id, window, cx);
        }
        // A click on an arrow goes to its other end.
        if e.button == MouseButton::Left
            && let Some((from, to)) = self.arrow_under(id, e.position)
            && let Some(listing) = &self.listing
            && let (Some(from), Some(to)) = (listing.line(from), listing.line(to))
        {
            let cursor = self.cursor_address(id);
            self.jump(arrows::other_end(from.address, to.address, cursor), cx);
            return;
        }
        let (Some(listing), Some(session)) = (self.listing.clone(), self.session.as_ref()) else {
            return;
        };
        let Some(db) = session.database() else {
            return;
        };
        if line >= listing.len() {
            return;
        }
        let rendered = listing.render(db, line, session.overlay());
        let hit = token_at(&rendered.tokens, col);
        // Ctrl+click or a middle click on a name: what it names in a new
        // tab.
        let named = hit
            .and_then(|i| rendered.tokens.get(i))
            .and_then(|t| t.target);

        if self.open_name(id, named, name_click(e, cx), window, cx) {
            return;
        }
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        // A left press may start a drag selecting lines (with Shift it
        // extends from the cursor); any other drops the selection.
        if e.button == MouseButton::Left {
            let cursor = state.listing.cursor;
            state
                .listing
                .selection
                .press(line, cursor, e.modifiers.shift);
        } else {
            state.listing.selection.clear();
        }
        state.listing.cursor = line;
        state.listing.token = hit;
        if let Some(t) = hit.and_then(|i| rendered.tokens.get(i)) {
            if highlightable(t.role) {
                state.listing.highlight = if state.listing.highlight.as_deref()
                    == Some(t.text.as_str())
                    && e.click_count == 1
                {
                    None
                } else {
                    Some(t.text.clone())
                };
            }
            if e.click_count == 2
                && t.role != Role::Prefix
                && let Some(target) = t.target
            {
                self.jump(target, cx);
                return;
            }
        }
        self.moved(id);
        cx.notify();
    }

    /// A right click: the cursor to the token (as a single click, the
    /// highlight kept), then its context menu; in the selection, the
    /// cursor and the selection stay (its commands take the selection).
    fn listing_right(
        &mut self,
        id: PaneId,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some((line, _, on_bar)) = self.listing_hit(id, e.position) else {
            return;
        };
        if on_bar {
            return;
        }
        if self
            .listing_selection(id)
            .is_some_and(|lines| lines.contains(&line))
        {
            if self.layout.focused() != id {
                self.focus_pane(id, window, cx);
            }
            self.open_context_menu(Surface::Listing, e.position, window, cx);
            return;
        }
        let highlight = self
            .panes
            .get(&id)
            .and_then(|s| s.listing.highlight.clone());
        let click = MouseDownEvent {
            click_count: 1,
            ..e.clone()
        };
        self.listing_down(id, &click, window, cx);
        if let Some(state) = self.panes.get_mut(&id)
            && state.listing.highlight.is_none()
        {
            state.listing.highlight = highlight;
        }
        self.open_context_menu(Surface::Listing, e.position, window, cx);
    }

    fn listing_move(
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
        if self.sideways_move(id, e) {
            cx.notify();
            return;
        }
        let Some((line, col, on_bar)) = self.listing_hit(id, e.position) else {
            return;
        };
        if e.dragging() && self.listing_drag(id, line) {
            cx.notify();
            return;
        }
        let arrow = self.arrow_under(id, e.position);
        if let Some(state) = self.panes.get_mut(&id)
            && state.listing.arrow != arrow
        {
            state.listing.arrow = arrow;
            cx.notify();
        }
        let (Some(listing), Some(session)) = (self.listing.clone(), self.session.as_ref()) else {
            return;
        };
        let Some(db) = session.database() else {
            return;
        };
        let info = listing.line(line).filter(|_| !on_bar);
        let hovered = info
            .filter(|l| l.kind == LineKind::Instruction)
            .map(|l| Link::Listing(l.address));
        let rendered = listing.render(db, line, session.overlay());
        let target = token_at(&rendered.tokens, col)
            .and_then(|i| rendered.tokens.get(i))
            .filter(|t| peekable(t.role))
            .and_then(|t| t.target)
            .filter(|_| info.is_some());
        if self.link != hovered {
            self.link = hovered;
            cx.notify();
        }
        self.hover_peek(target, None, e.position, window, cx);
    }

    /// A drag from a press in pane `id`'s listing onto line `line`: the
    /// cursor follows it, the lines from the one pressed selected; whether
    /// it was such a drag.
    fn listing_drag(&mut self, id: PaneId, line: u64) -> bool {
        let len = self.listing.as_ref().map_or(0, |l| l.len());
        let Some(state) = self.panes.get_mut(&id) else {
            return false;
        };
        let line = line.min(len.saturating_sub(1));
        if !state.listing.selection.drag(line) {
            return false;
        }
        if state.listing.cursor != line {
            state.listing.cursor = line;
            state.listing.token = None;
            self.moved(id);
        }
        true
    }

    /// Pane `id`'s scrolling by lines, as its scrollbar moves it: the
    /// shown view's (the listing's, the C's or the IR's), its lines and
    /// the rows shown, and the track's length and where `y` is along it.
    fn line_scroll(
        &mut self,
        id: PaneId,
        y: gpui_kit::Pixels,
    ) -> Option<(&mut Scroller, u64, u64, f32, f32)> {
        let ir = self.shows_ir(id);
        let c = matches!(self.layout.active(id), Some(TabKind::C { .. }));
        let rows = self.rows(id, self.line_height(id));
        let unified = self.shows_unified(id);
        let total = if unified {
            self.panes
                .get(&id)
                .and_then(|s| s.unified.flat.as_ref())
                .map_or(0, |f| f.len() as u64)
        } else if ir {
            self.ir_total(id)
        } else if c {
            self.layout
                .active(id)
                .and_then(|k| self.document(k))
                .map_or(0, |d| d.lines.len() as u64)
        } else {
            self.listing.as_ref().map_or(0, |l| l.len())
        };
        let state = self.panes.get_mut(&id)?;
        let b = state.bounds.get();
        let scroll = if unified {
            &mut state.unified.scroll
        } else if ir {
            &mut state.ir.scroll
        } else if c {
            &mut state.c.scroll
        } else {
            &mut state.listing.scroll
        };
        scroll.smooth.stop();
        Some((
            scroll,
            total,
            rows,
            f32::from(b.size.height),
            f32::from(y - b.origin.y),
        ))
    }

    /// A left press on pane `id`'s scrollbar at `y`: on the thumb a drag
    /// from where it was taken, beside it a page that way.
    pub fn scrollbar_down(&mut self, id: PaneId, y: gpui_kit::Pixels) {
        let least = self.row(22.0);
        let Some((scroll, total, rows, track, at)) = self.line_scroll(id, y) else {
            return;
        };
        match scroll.anchor.thumb(track, total, rows, least).press(at) {
            Press::Before => scroll.anchor.page(false, total, rows),
            Press::After => scroll.anchor.page(true, total, rows),
            Press::On(grab) => self.scrollbar_drag = Some((id, grab)),
        }
    }

    /// A move in pane `id` dragging its scrollbar's thumb; whether it was
    /// such a drag.
    pub fn scrollbar_move(&mut self, id: PaneId, e: &MouseMoveEvent) -> bool {
        let Some((_, grab)) = self.scrollbar_drag.filter(|&(pane, _)| pane == id) else {
            return false;
        };
        if !e.dragging() {
            return false;
        }
        let least = self.row(22.0);
        if let Some((scroll, total, rows, track, at)) = self.line_scroll(id, e.position.y) {
            scroll
                .anchor
                .drag_thumb(at - grab, track, total, rows, least);
        }
        true
    }

    /// The branch-arrow gutter of `lines` ([`arrows`]), and where its
    /// arrows are, for the pointer: the arrows with an end on the cursor's
    /// item and the one under the pointer at full strength, the latter
    /// naming its target in a tooltip (`jz → loc_1E745`).
    fn arrows(
        &self,
        id: PaneId,
        listing: &Listing,
        lines: Range<u64>,
        db: &Database<'_>,
        overlay: &Overlay,
        cx: &mut Context<Self>,
    ) -> (AnyElement, Vec<Hit>) {
        let theme = self.theme;
        let Some(state) = self.panes.get(&id) else {
            return (div().into_any_element(), Vec::new());
        };
        let row_h = self.row(self.settings.listing_line_height);
        let rows = self.rows(id, self.settings.listing_line_height);
        let g = Geometry {
            width: self.gutter_width(),
            lane: self.row(LANE),
            gap: self.row(GAP),
            lanes: usize::try_from(self.settings.arrow_lanes).unwrap_or(usize::MAX),
            row: row_h,
            height: f(rows) * row_h,
            first: state.listing.scroll.anchor.line,
            offset: state.listing.scroll.anchor.offset,
            label_char: self.char_width.unwrap_or(8.0) * LABEL_SCALE,
            stubs: arrows::StubStyle::Labelled,
        };
        let address = |line: u64| listing.line(line).map(|l| l.address);
        let cursor = address(state.listing.cursor);
        let hovered = state.listing.arrow;
        let on = |a: &Arrow| {
            hovered == Some((a.from, a.to))
                || (cursor.is_some() && (address(a.from) == cursor || address(a.to) == cursor))
        };
        let label = |a: &Arrow, end: End, room: usize| {
            let other = address(if end == End::Source { a.to } else { a.from }).unwrap_or(0);
            let name = (end == End::Source)
                .then(|| listing.shown_name(other, overlay))
                .flatten();
            arrows::stub_label(end, name, other, room)
        };
        let drawn = arrows::lay_out(
            &g,
            &listing.arrows(lines),
            &theme.arrows(),
            arrows::dim(theme.dark),
            on,
            label,
        );
        let label_size = self.code_size() * LABEL_SCALE;
        let labels = drawn.labels.into_iter().map(|l| {
            div()
                .absolute()
                .top(px(l.y - row_h / 2.0))
                .right(px(g.width - l.right))
                .h(px(row_h))
                .px(px(2.0))
                .flex()
                .items_center()
                .rounded(px(2.0))
                .bg(hsla(theme.editor))
                .text_size(px(label_size))
                .text_color(hsla(l.color))
                .child(l.text)
        });
        let tip = hovered
            .and_then(|(from, to)| Some((from, to, arrow_tip(listing, db, overlay, from, to)?)));
        let gutter = div()
            .absolute()
            .top_0()
            .left_0()
            .w(px(g.width))
            .h_full()
            .child(arrows::paint(drawn.quads))
            .children(labels)
            .when_some(tip, |d, (from, to, text)| {
                // Keyed by the arrow, so another arrow's tooltip starts
                // afresh; leaving the gutter lets the arrow go.
                d.child(
                    div()
                        .id(ElementId::NamedInteger(format!("arrow-{to}").into(), from))
                        .absolute()
                        .size_full()
                        .tooltip(move |window, cx| Tooltip::new(text.clone()).build(window, cx))
                        .on_hover(cx.listener(move |this, hovered: &bool, _, cx| {
                            if !*hovered && let Some(state) = this.panes.get_mut(&id) {
                                state.listing.arrow = None;
                                cx.notify();
                            }
                        })),
                )
            });
        (gutter.into_any_element(), drawn.hits)
    }
}

/// The tooltip of the arrow from line `from` to line `to`: its jump's
/// mnemonic and its target's name (`jz → loc_1E745`).
fn arrow_tip(
    listing: &Listing,
    db: &Database<'_>,
    overlay: &Overlay,
    from: u64,
    to: u64,
) -> Option<String> {
    let rendered = listing.render(db, from, overlay);
    let mnemonic = rendered.tokens.iter().find(|t| t.role == Role::Mnemonic)?;
    let target = listing.line(to)?.address;
    let name = listing
        .shown_name(target, overlay)
        .map_or_else(|| listing.describe(target), str::to_owned);
    Some(format!("{} → {name}", mnemonic.text.trim()))
}

/// The column under `x` pixels for characters `width` wide.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a column on screen"
)]
pub fn column(x: f32, width: f32) -> usize {
    (x / width.max(1.0)).floor().max(0.0) as usize
}

/// `alpha` (0–255) as a byte.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "clamped to a byte"
)]
fn alpha_u8(alpha: f32) -> u8 {
    alpha.clamp(0.0, 255.0) as u8
}

/// The token at character `col` of `tokens`.
pub fn token_at(tokens: &[Token], col: usize) -> Option<usize> {
    let mut at = 0;
    for (i, t) in tokens.iter().enumerate() {
        let n = t.text.chars().count();
        if col >= at && col < at + n {
            return Some(i);
        }
        at += n;
    }
    None
}

/// Whether clicking a token of `role` highlights its equals.
pub(crate) fn highlightable(role: Role) -> bool {
    matches!(
        role,
        Role::Prefix
            | Role::Mnemonic
            | Role::JumpMnemonic
            | Role::CallMnemonic
            | Role::ReturnMnemonic
            | Role::PaddingMnemonic
            | Role::Register
            | Role::Number
            | Role::CodeName
            | Role::DataName
            | Role::ImportName
            | Role::LocalName
    )
}

/// Whether hovering a token of `role` peeks at its target.
pub(crate) fn peekable(role: Role) -> bool {
    matches!(
        role,
        Role::CodeName | Role::DataName | Role::ImportName | Role::CodeXref | Role::DataXref
    )
}

/// `text` as runs of (bytes, dimmer tone): a hexadecimal number of five
/// digits or more (if `numeric`) has its 4-digit groups, from the right,
/// alternately in the base and the dimmer tone;
/// anything else is one run in the base tone.
pub fn tones(text: &str, numeric: bool) -> Vec<(usize, bool)> {
    let whole = vec![(text.len(), false)];
    if !numeric {
        return whole;
    }
    // The longest run of hex digits (after a `0x` or a `seg:`).
    let bytes = text.as_bytes();
    let mut best = (0, 0);
    let mut start = None;
    for (i, b) in bytes
        .iter()
        .enumerate()
        .chain(std::iter::once((bytes.len(), &b' ')))
    {
        if b.is_ascii_hexdigit() {
            start.get_or_insert(i);
        } else if let Some(s) = start.take()
            && i - s > best.1 - best.0
        {
            best = (s, i);
        }
    }
    let (s, e) = best;
    if e - s < 5 {
        return whole;
    }
    let mut runs = Vec::new();
    if s > 0 {
        runs.push((s, false));
    }
    let digits = e - s;
    let head = digits % 4;
    let groups = digits / 4;
    // Group k from the right: even k base, odd k dimmer.
    let mut k = groups + usize::from(head > 0);
    if head > 0 {
        k -= 1;
        runs.push((head, k % 2 == 1));
    }
    for _ in 0..groups {
        k -= 1;
        runs.push((4, k % 2 == 1));
    }
    if e < text.len() {
        runs.push((text.len() - e, false));
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::tones;

    #[test]
    fn long_hex_numbers_alternate_by_four_digit_groups_from_the_right() {
        assert_eq!(
            tones(".text:0001C6C0", true),
            vec![(6, false), (4, true), (4, false)]
        );
        assert_eq!(
            tones("1C6C0h", true),
            vec![(1, true), (4, false), (1, false)]
        );
        assert_eq!(
            tones("0x12345678ABCD", true),
            vec![(2, false), (4, false), (4, true), (4, false)]
        );
        assert_eq!(tones("88h", true), vec![(3, false)]);
        assert_eq!(tones("0001C6C0", false), vec![(8, false)]);
    }
}
