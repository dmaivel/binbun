//! A C pane: the function's C in rows, a line-number gutter whose numbers
//! carry the statements' link tints, the tokens a hovered instruction
//! came to, and the rename field in place (a variable's or a member's:
//! every occurrence edited at once, a variable's default name dimmed when
//! emptied; a double click on a variable or member opens it, on a
//! function's or global's name follows it). A right click moves the
//! cursor to the token and opens its context menu. The user's comments
//! read `// text` in the listing's comment colour; the comment field opens
//! in place after the statement, the line's comment lines giving way to
//! it. Ctrl+click or a middle click on a function's or a global's name
//! opens it in a new tab. A tab whose place is in no function (its
//! function deleted under it) says so.
//! A drag selects characters across lines, a double click a token (a
//! variable's or a member's opens its field, a name follows it), a triple
//! click a line; Shift with a click or the keys extends from the cursor.
//! The selection is washed in the selection's colour over the others'
//! selections in their colours.

use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

use binbun_gui_view::cdoc::{CDocument, CardLine, Field, Named, Reveal, UndefinedValue};
use binbun_gui_view::context::Surface;
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::listing::Role;
use binbun_gui_view::peek::{RunValue, undefined_note};
use binbun_gui_view::selection::{Text, TextPos, byte_at, c_line, c_token, column_at, columns_on};
use binbun_gui_view::tabs::{CSubject, c_subject};
use binbun_gui_view::talk::c_marks;
use binbun_gui_view::{CTokenKind, FunctionId, MemberEdit, Node, View};
use gpui_kit::base::Input as FieldInput;
use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, Hsla, KeyDownEvent, MouseButton, MouseDownEvent, MouseMoveEvent, Pixels,
    Point, ScrollEvent, StyledText, TextRun, Window, div, px,
};

use crate::collab::{c_column, caret_bar, caret_wash, selection_wash};
use crate::facts_view::FoundReveals;
use crate::highlight::Highlight;
use crate::listing_view::{SCROLLBAR, column, tones};
use crate::panes::measured;
use crate::scrolling::scrolled;
use crate::search_view::{FindKind, bookmarked_lines, marked};
use crate::struct_editor::GUTTER;
use crate::tabs::name_click;
use crate::theme::{dim, hsla, solid, with_alpha};
use crate::workspace::{CHighlight, FieldEdit, Link, Renamed, TabKind, Workspace, f};

/// The C text's left margin after the gutter (logical pixels).
const PAD: f32 = 12.0;
/// The width of a reveal mark at the gutter's left edge (pixels); the
/// bookmark bars start a pixel past it.
const REVEAL: f32 = 3.0;

impl Workspace {
    /// The C gutter's width for `document` in pane `id`, zoomed: the line
    /// numbers', or the struct editor's while a definition is edited in
    /// place there.
    fn c_gutter(&self, id: PaneId, document: &CDocument) -> f32 {
        let digits = document.lines.len().max(1).to_string().len().max(3);
        let chars = if self.inline_struct.as_ref().is_some_and(|s| s.pane == id) {
            GUTTER.max(digits as u64 + 2)
        } else {
            digits as u64 + 2
        };
        self.char_width.unwrap_or(8.0) * f(chars)
    }

    /// The reveal mark of line `n` of pane `id`'s reading view: a faint
    /// bar at the gutter's edge, the gutter's row its hover area (the
    /// pointer on it shows the exact C there).
    fn reveal_mark(
        &self,
        id: PaneId,
        n: usize,
        row_h: f32,
        gutter: f32,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        div()
            .id(("reveal", n))
            .absolute()
            .left_0()
            .top_0()
            .w(px(gutter))
            .h(px(row_h))
            .on_hover(cx.listener(move |this, hovered: &bool, _, cx| {
                if let Some(state) = this.panes.get_mut(&id) {
                    let reveal = hovered.then_some(n);
                    if *hovered || state.c.reveal == Some(n) {
                        state.c.reveal = reveal;
                        cx.notify();
                    }
                }
            }))
            .child(
                div()
                    .absolute()
                    .left_0()
                    .top(px(row_h * 0.25))
                    .w(px(REVEAL))
                    .h(px(row_h * 0.5))
                    .bg(hsla(self.theme.text_placeholder)),
            )
            .into_any_element()
    }

    /// The card of a reveal: `exact`'s `lines` (the exact C where the
    /// reading view hid checks, each check in its short form), their
    /// shared indentation dropped, in a card as the peek and why cards,
    /// over the text past the `gutter`:
    /// below the marked line (its top at `marked`), or above it where a
    /// pane of `height` has no room below; never over it.
    fn reveal_card(
        &self,
        exact: &CDocument,
        lines: &[usize],
        marked: f32,
        height: f32,
        (gutter, row_h): (f32, f32),
    ) -> AnyElement {
        let theme = self.theme;
        let indent = exact.indent(lines);
        let shown_lines = exact.card_lines(lines);
        let count = shown_lines.len();
        let rows = shown_lines.into_iter().map(|line| {
            let n = match line {
                CardLine::Line(n) => n,
                CardLine::Check { text, .. } => {
                    // The macro as a call, its argument as the C's text.
                    let text = text.get(indent.min(text.len())..).unwrap_or("").to_owned();
                    let call = text.find('(').unwrap_or(text.len());
                    let name_start = text.len() - text.trim_start().len();
                    let runs = vec![
                        self.text_run(name_start, theme.variable, None),
                        self.text_run(call - name_start, theme.c_kind(CTokenKind::Macro), None),
                        self.text_run(text.len() - call, theme.variable, None),
                    ];
                    let runs: Vec<TextRun> = runs.into_iter().filter(|r| r.len > 0).collect();
                    return div()
                        .h(px(row_h))
                        .whitespace_nowrap()
                        .child(StyledText::new(text).with_runs(runs));
                }
            };
            let shown = exact.shown_line(n, None);
            let runs: Vec<TextRun> = shown
                .pieces
                .iter()
                .map(|piece| {
                    let color = piece
                        .span
                        .and_then(|s| exact.spans.get(s))
                        .map_or(theme.variable, |span| theme.c(span));
                    self.text_run(piece.range.len(), color, None)
                })
                .collect();
            let from = indent.min(shown.text.len());
            let runs = runs_covering(&runs, from, shown.text.len());
            let text = shown.text.get(from..).unwrap_or("").to_owned();
            div()
                .h(px(row_h))
                .whitespace_nowrap()
                .child(StyledText::new(text).with_runs(runs))
        });
        let (pad, gap) = (f32::from(self.z(6.0)), f32::from(self.z(3.0)));
        // Its lines, the padding and the border.
        let card_h = f(count as u64) * row_h + 2.0 * pad + 2.0;
        let below = marked + row_h + gap;
        let above = marked - gap - card_h;
        let top = if below + card_h > height && above >= 0.0 {
            above
        } else {
            below
        };
        self.card()
            .absolute()
            .top(px(top))
            .left(px(gutter) + self.z(PAD))
            .px(self.z(10.0))
            .py(px(pad))
            .children(rows)
            .into_any_element()
    }

    /// Pane `id`'s C.
    #[expect(clippy::too_many_lines, reason = "one row's layers, in order")]
    pub fn render_c(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let row_h = self.row(self.settings.c_line_height);
        let rows = self.rows(id, self.settings.c_line_height);
        let kind = self.layout.active(id).cloned();
        // A struct's definition edited in place: its lines and its rows.
        let block = kind
            .as_ref()
            .and_then(|k| self.document(k).cloned())
            .and_then(|document| self.inline_block(id, &document));
        let editing = self.field.as_ref().is_some_and(|e| e.pane == id)
            || self.comment.as_ref().is_some_and(|c| c.pane == id)
            || block.is_some();
        // The text scrolled sideways, the cursor kept in view.
        let char_w = self.char_width.unwrap_or(8.0);
        let pad = f32::from(self.z(PAD));
        let sx = match kind.as_ref().and_then(|k| self.document(k)).cloned() {
            Some(document) => {
                let gutter = self.c_gutter(id, &document);
                let cursor = self.panes.get(&id).map(|s| {
                    let caret = pad + f(s.c.column as u64) * char_w;
                    (
                        (s.c.line as u64, s.c.column as u64),
                        (caret - 4.0 * char_w, caret + 4.0 * char_w),
                    )
                });
                self.follow_sideways(id, gutter, cursor)
            }
            None => 0.0,
        };
        let Some(state) = self.panes.get(&id) else {
            return div().into_any_element();
        };
        let bounds = Rc::clone(&state.bounds);
        let mut pane = div()
            .id(("c", id.0))
            .key_context(if editing { "CEdit" } else { "Code" })
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
                    this.c_down(id, e, window, cx);
                }),
            )
            .on_mouse_down(
                MouseButton::Middle,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.c_down(id, e, window, cx);
                }),
            )
            .on_mouse_down(
                MouseButton::Right,
                cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                    this.c_right(id, e, window, cx);
                }),
            )
            .on_mouse_move(cx.listener(move |this, e: &MouseMoveEvent, window, cx| {
                this.c_move(id, e, window, cx);
            }))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |this, _, _, _| {
                    this.scrollbar_drag = None;
                    this.sideways_drag = None;
                    if let Some(state) = this.panes.get_mut(&id) {
                        let cursor = TextPos::new(state.c.line, state.c.column);
                        state.c.selection.release(cursor);
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
            .when(editing, |d| {
                // A click outside the pane drops the field (inside, the
                // click itself does).
                d.on_mouse_down_out(cx.listener(|this, _, window, cx| {
                    this.close_overlays(window, cx);
                    cx.notify();
                }))
            })
            .child(measured(bounds).absolute().size_full());
        let pending = match &kind {
            Some(TabKind::C {
                function: Some(f),
                view,
            }) => self
                .session
                .as_ref()
                .is_some_and(|s| s.is_pending(*f, *view)),
            _ => false,
        };
        if pending {
            pane = pane.child(self.loading_bar(id, window));
        }
        let Some(document) = kind.as_ref().and_then(|k| self.document(k)).cloned() else {
            // No function at the tab's place: it says so, where it is.
            let function = if let Some(TabKind::C { function, .. }) = &kind {
                *function
            } else {
                None
            };
            let place = self.layout.active_tab(id).and_then(|t| self.places.at(t));
            // The function's C cannot be printed: why, as the CLI says it.
            let failure = match &kind {
                Some(TabKind::C {
                    function: Some(f),
                    view,
                }) => self
                    .session
                    .as_ref()
                    .and_then(|s| s.failure(*f, *view))
                    .map(str::to_owned),
                _ => None,
            };
            let said = match c_subject(function, place) {
                CSubject::Outside(address) => Some(format!("{address:X} is not in a function")),
                CSubject::Function(_) | CSubject::Nothing => failure,
            };
            if let Some(said) = said {
                pane = pane.child(
                    div()
                        .absolute()
                        .size_full()
                        .flex()
                        .items_center()
                        .justify_center()
                        .px(self.z(16.0))
                        .font_family(self.settings.ui_font.clone())
                        .text_size(self.z(self.settings.ui_font_size))
                        .text_color(hsla(theme.text_muted))
                        .child(said),
                );
            }
            return pane.into_any_element();
        };
        let gutter = self.c_gutter(id, &document);
        // A committed rename is shown until its document is replaced.
        if self
            .renamed
            .as_ref()
            .is_some_and(|r| r.pane == id && !Arc::ptr_eq(&r.document, &document))
        {
            self.renamed = None;
        }
        let field = self
            .field
            .as_ref()
            .filter(|e| e.pane == id)
            .map(|e| &e.field)
            .or_else(|| {
                self.renamed
                    .as_ref()
                    .filter(|r| r.pane == id)
                    .map(|r| &r.field)
            });
        let hovered: Vec<usize> = match &self.link {
            Some(Link::Listing(address)) => document.spans_of(*address),
            Some(Link::C { .. }) | None => Vec::new(),
        };
        let focused = self.layout.focused() == id;
        let why = self.why_marks(&document);
        let values = self.run_values(&document);
        // The reading view's hidden checks: a mark on each line hiding
        // one, its card the exact C there.
        let exact = self
            .session
            .as_ref()
            .and_then(|s| s.document(document.function, View::Exact))
            .filter(|_| !document.assumed().is_empty())
            .cloned();
        let reveals = self.reveals_of(&document, exact.as_deref());
        let inside = |address: u64| {
            self.listing
                .as_ref()
                .and_then(|l| l.function_of(address))
                .is_some_and(|(f, _)| f == document.function)
        };
        let bookmarked = bookmarked_lines(&document, &self.bookmark_colors(), inside);
        let talked = c_marks(&self.threads.all, &document, inside);
        // The others' cursors in a shared session.
        let remote = self.c_carets(&document);
        // The others' selections, then this one's.
        let selections: Vec<((TextPos, TextPos), Hsla)> = self
            .c_selections(&document)
            .into_iter()
            .chain(
                state
                    .c
                    .selection
                    .range(TextPos::new(state.c.line, state.c.column))
                    .map(|range| (range, hsla(theme.selection))),
            )
            .collect();
        let mut carets: Vec<AnyElement> = Vec::new();
        let mut own = None;
        let find = FindKind::C(document.function, document.view);
        let mut card = None;
        let first = state.c.scroll.anchor.line;
        let offset = state.c.scroll.anchor.offset;
        // The rows the block's lines take more (or fewer) than they had.
        let extra = block.as_ref().map_or(0, |(lines, edited)| {
            u64::try_from(lines.len().max(*edited)).unwrap_or(0)
        });
        // The comment field: its line, the lines its comments take now.
        let commenting = self
            .comment
            .as_ref()
            .filter(|c| c.pane == id)
            .and_then(|c| Some((c, c.line?)))
            .map(|(c, n)| (c, n, document.comment_lines(n)));
        let freed = commenting.as_ref().map_or(0, |(c, _, lines)| {
            u64::try_from(lines.len().saturating_sub(c.field.lines())).unwrap_or(0)
        });
        let mut field_box = None;
        // The widest line drawn, from the text's left edge.
        let mut widest: f32 = 0.0;
        if let (Ok(from), Ok(to)) = (
            usize::try_from(first),
            usize::try_from(first.saturating_add(rows + extra + freed + 1)),
        ) {
            self.drawn_c(&document, from..to);
        }
        for k in 0..=rows + extra + freed {
            let Some(n) = usize::try_from(first + k).ok() else {
                break;
            };
            let Some(line) = document.lines.get(n) else {
                break;
            };
            if block.as_ref().is_some_and(|(lines, _)| lines.contains(&n)) {
                continue;
            }
            if commenting
                .as_ref()
                .is_some_and(|(_, at, lines)| lines.contains(&n) && n != *at)
            {
                continue;
            }
            let grown = commenting
                .as_ref()
                .filter(|(_, _, lines)| n >= lines.end)
                .map_or(0.0, |(c, _, lines)| {
                    (f(c.field.lines() as u64) - f(lines.len() as u64)) * row_h
                });
            let shift = grown
                + block
                    .as_ref()
                    .filter(|(lines, _)| n >= lines.end)
                    .map_or(0.0, |(lines, edited)| {
                        (f(*edited as u64) - f(lines.len() as u64)) * row_h
                    });
            let background = (n == state.c.line).then_some(if focused {
                theme.active_line
            } else {
                theme.lit()
            });
            let shown = document.shown_line(n, field);
            let runs: Vec<TextRun> = shown
                .pieces
                .iter()
                .flat_map(|piece| {
                    let len = piece.range.len();
                    let Some(s) = piece.span else {
                        return vec![self.text_run(len, theme.variable, None)];
                    };
                    let Some(span) = document.spans.get(s) else {
                        return vec![self.text_run(len, theme.variable, None)];
                    };
                    let lit = match &state.c.highlight {
                        Some(CHighlight::Node(node)) => {
                            span.node == Some(*node) && span.kind.is_variable()
                        }
                        Some(CHighlight::Text(t)) => document.span_text(s) == t,
                        None => false,
                    };
                    let back = if lit {
                        Some(theme.search_match)
                    } else if hovered.contains(&s) {
                        Some(theme.selection)
                    } else if span
                        .node
                        .is_some_and(|node| self.origin_node(&document, node))
                    {
                        Some(with_alpha(theme.accent, 0x30))
                    } else {
                        None
                    };
                    let text = shown.text.get(piece.range.clone()).unwrap_or("");
                    let color = if piece.placeholder {
                        theme.text_placeholder
                    } else if document.comments.contains_key(&s) {
                        theme.role(Role::Comment)
                    } else {
                        theme.c(span)
                    };
                    let numeric = span.kind == CTokenKind::Number && text.starts_with("0x");
                    tones(text, numeric)
                        .into_iter()
                        .map(|(len, tone)| {
                            self.text_run(len, if tone { dim(color) } else { color }, back)
                        })
                        .collect()
                })
                .collect();
            // A field typed into reads otherwise than the matches found.
            let runs = if shown.field.is_none() {
                marked(runs, &self.find_marks(id, &find, n as u64))
            } else {
                runs
            };
            let number = format!(
                "{:>w$} ",
                n + 1,
                w = document.lines.len().to_string().len().max(3)
            );
            let number_color = if n == state.c.line {
                theme.active_line_number
            } else {
                theme.line_number
            };
            let y = f(k) * row_h - offset + shift;
            let len = document.line_text(n).chars().count();
            let left = gutter + f32::from(self.z(PAD));
            let washes = selections.iter().filter_map(|&(range, color)| {
                let (start, end) = columns_on(range, n, len)?;
                let x = left + f(start as u64) * char_w;
                let width = f((end - start) as u64) * char_w;
                Some(selection_wash(color, (x, Some(width)), row_h))
            });
            let reveal = reveals.get(&n).map(|reveal| {
                if state.c.reveal == Some(n) && !reveal.exact.is_empty() {
                    card = exact
                        .as_ref()
                        .map(|exact| (Arc::clone(exact), reveal.exact.clone(), y));
                }
                self.reveal_mark(id, n, row_h, gutter, cx)
            });
            let mut row = div()
                .absolute()
                .top(px(y))
                .left_0()
                .right(self.z(SCROLLBAR))
                .h(px(row_h))
                .overflow_hidden()
                .when_some(background, |d, b| d.bg(hsla(b)));
            // The gutter stays put; the rest, laid out from the row's left
            // edge, scrolls sideways past it.
            let numbers = div()
                .absolute()
                .top_0()
                .left_0()
                .w(px(gutter))
                .h_full()
                .text_color(hsla(number_color))
                .when_some(line.tint, |d, t| d.bg(hsla(theme.tint(t))))
                .child(number)
                .children(reveal)
                .when_some(bookmarked.get(&n), |d, colors| {
                    // Past the reveal mark: the first bar a pixel after it
                    // (at 100%).
                    d.children(self.bookmark_marks(colors, row_h, REVEAL - 1.0))
                });
            let mut body = div()
                .flex()
                .whitespace_nowrap()
                .children(washes)
                .child(div().flex_none().w(px(gutter)));
            let text = div().flex().flex_none().pl(self.z(PAD));
            let editing_line = shown.field.is_some() && editing;
            // Weak evidence: a dotted underline under each marked token.
            let marks: Vec<AnyElement> = why
                .as_ref()
                .filter(|_| !editing_line)
                .map(|why| {
                    line.spans
                        .clone()
                        .filter(|s| why.marks.contains_key(s))
                        .filter_map(|s| {
                            let span = document.spans.get(s)?;
                            let before = document.text.get(line.range.start..span.range.start)?;
                            let chars = document.text.get(span.range.clone())?.chars().count();
                            let x = gutter
                                + f32::from(self.z(PAD))
                                + f(before.chars().count() as u64) * char_w;
                            Some(
                                div()
                                    .absolute()
                                    .left(px(x))
                                    .bottom(px(1.0))
                                    .w(px(f(chars as u64) * char_w))
                                    .h(px(1.0))
                                    .border_b_1()
                                    .border_dashed()
                                    .border_color(hsla(theme.text_muted))
                                    .into_any_element(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            // A value the run's processor profile gave is in the accent,
            // the processor named after it.
            let processor = values.as_ref().and_then(|v| v.processor.as_deref());
            let pills: Vec<AnyElement> = values
                .as_ref()
                .and_then(|v| v.lines.get(&n))
                .into_iter()
                .flatten()
                .map(|pill| {
                    let mark = processor.filter(|_| pill.profile);
                    div()
                        .flex()
                        .flex_none()
                        .gap(self.z(4.0))
                        .px(self.z(4.0))
                        .rounded(self.z(3.0))
                        .bg(hsla(theme.element_hover))
                        .text_color(hsla(if mark.is_some() {
                            theme.accent
                        } else {
                            theme.text_muted
                        }))
                        .child(pill.text.clone())
                        .when_some(mark, |d, mark| {
                            d.child(
                                div()
                                    .text_color(hsla(theme.text_muted))
                                    .child(mark.to_owned()),
                            )
                        })
                        .into_any_element()
                })
                .collect();
            let stub = values
                .as_ref()
                .and_then(|v| v.stub.clone())
                .filter(|(at, _)| *at == n)
                .map(|(_, callee)| self.stub_button(&document, callee, cx));
            // The line's width: its text, then its values and stub button
            // (their padding and gaps, roughly).
            let tail = values
                .as_ref()
                .and_then(|v| v.lines.get(&n))
                .into_iter()
                .flatten()
                .map(|pill| {
                    let mark = processor.filter(|_| pill.profile);
                    let chars =
                        pill.text.chars().count() + mark.map_or(0, |m| m.chars().count() + 1);
                    f(chars as u64) * char_w + f32::from(self.z(12.0))
                })
                .sum::<f32>()
                + if stub.is_some() {
                    f32::from(self.z(20.0))
                } else {
                    0.0
                };
            let tail = if tail > 0.0 {
                tail + f32::from(self.z(16.0))
            } else {
                0.0
            };
            widest = widest.max(pad + f(shown.text.chars().count() as u64 + 2) * char_w + tail);
            let owner = commenting
                .as_ref()
                .filter(|(_, at, _)| *at == n)
                .map(|(c, ..)| *c);
            let text = match (
                shown.field.and_then(|at| shown.pieces.get(at)),
                self.field.as_ref().filter(|e| e.pane == id),
                owner,
            ) {
                // The line's code, then `// ` where the field goes.
                (_, _, Some(edit)) => {
                    let end = document.code_end(n).min(shown.text.len());
                    let code = shown.text.get(..end).unwrap_or("");
                    let mut code_runs = runs_covering(&runs, 0, end);
                    code_runs.push(self.text_run(4, theme.role(Role::Comment), None));
                    let x = gutter
                        + f32::from(self.z(PAD))
                        + f(code.chars().count() as u64 + 4) * char_w;
                    field_box = Some(self.comment_box(edit, x - sx, y, row_h));
                    text.child(StyledText::new(format!("{code} // ")).with_runs(code_runs))
                }
                (Some(piece), Some(edit), None) => {
                    let before = shown.text[..piece.range.start].to_owned();
                    let after = shown.text[piece.range.end..].to_owned();
                    let before_runs = runs_covering(&runs, 0, piece.range.start);
                    let after_runs = runs_covering(&runs, piece.range.end, shown.text.len());
                    let columns: usize = shown.text[piece.range.clone()]
                        .chars()
                        .map(|c| if c >= '\u{1100}' { 2 } else { 1 })
                        .sum();
                    let width = f(columns.max(1) as u64 + 2) * self.char_width.unwrap_or(8.0);
                    text.items_center()
                        .when(!before.is_empty(), |d| {
                            d.child(StyledText::new(before).with_runs(before_runs))
                        })
                        .child(
                            div()
                                .w(px(width))
                                .h(px(row_h - 2.0))
                                // The input lays its line out at the line
                                // height it inherits: the box's inside, so
                                // the name sits where the line's text does.
                                .line_height(px(row_h - 4.0))
                                .bg(hsla(solid(theme.editor)))
                                .border_1()
                                .rounded(px(2.0))
                                .border_color(hsla(if edit.error {
                                    theme.error
                                } else {
                                    theme.border_focused
                                }))
                                .text_color(hsla(theme.text))
                                // A click in the field moves its caret; the
                                // pane's own click would close the field.
                                .on_mouse_down(MouseButton::Left, |_, _, cx| {
                                    cx.stop_propagation();
                                })
                                .child(FieldInput::new(&edit.input)),
                        )
                        .when(!after.is_empty(), |d| {
                            d.child(StyledText::new(after).with_runs(after_runs))
                        })
                }
                _ => text.child(StyledText::new(shown.text).with_runs(runs)),
            };
            body = body.child(text);
            body = body.when(!pills.is_empty() || stub.is_some(), |d| {
                d.child(
                    div()
                        .flex()
                        .flex_none()
                        .items_center()
                        .gap(self.z(4.0))
                        .ml(self.z(16.0))
                        .children(pills)
                        .children(stub),
                )
            });
            let here: Vec<_> = remote.get(&n).into_iter().flatten().collect();
            if !here.is_empty() {
                body = body.child(self.line_badges(&here, row_h));
            }
            body = body.children(marks);
            row = row.child(scrolled(gutter, sx, body)).child(numbers);
            // A thread's mark sits in the margin between the numbers and
            // the text.
            if let Some(mark) = talked.get(&n) {
                row = row.child(self.thread_mark(
                    ("c-thread", n),
                    &mark.threads,
                    mark.resolved,
                    (gutter + 0.5, row_h),
                    cx,
                ));
            }
            // A caret scrolled under the gutter is not drawn.
            let caret_at =
                |column: f32| Some(gutter + pad + column * char_w - sx).filter(|&x| x >= gutter);
            for caret in &here {
                row = row.child(caret_wash(caret, row_h));
                let column = caret.column.unwrap_or_else(|| c_column(&document, n, None));
                if let Some(x) = caret_at(f(u64::from(column))) {
                    carets.push(caret_bar(caret.color, (x, y, row_h)));
                }
            }
            // One's own caret, as the others' are drawn (not while a field
            // or a struct in the pane takes the typing: it has its own).
            if n == state.c.line && !editing {
                let column = state.c.column.min(len);
                own = caret_at(f(column as u64))
                    .map(|x| caret_bar(self.own_caret(focused), (x, y, row_h)));
            }
            pane = pane.child(row);
        }
        pane = pane.children(carets).children(own);
        if let Some((exact, lines, marked)) = card {
            let height = f(rows) * row_h;
            pane = pane.child(self.reveal_card(&exact, &lines, marked, height, (gutter, row_h)));
        }
        pane = pane.children(field_box);
        if let Some((lines, _)) = &block {
            let top = (f(lines.start as u64) - f(first)) * row_h - offset;
            pane = pane.children(self.render_inline_struct(id, top, gutter, row_h));
        }
        let total = document.lines.len() as u64;
        let bar = self.scrollbar(id, total, state.c.line as u64, state.c.scroll.anchor, rows);
        pane.child(bar)
            .children(self.measured_sideways(id, gutter, widest))
            .into_any_element()
    }

    /// A thin bar sweeping along the top while the C is on its way (no
    /// caption: the restraint rule).
    pub(crate) fn loading_bar(&self, id: PaneId, window: &mut Window) -> AnyElement {
        window.request_animation_frame();
        let width = self
            .panes
            .get(&id)
            .map_or(800.0, |s| f32::from(s.bounds.get().size.width))
            .max(1.0);
        let bar = width / 4.0;
        let phase = (crate::STARTED.elapsed().as_secs_f32() / 1.2).fract();
        div()
            .absolute()
            .top_0()
            .h(px(2.0))
            .left(px(phase * (width + bar) - bar))
            .w(px(bar))
            .bg(hsla(self.theme.accent))
            .into_any_element()
    }

    /// The line and the byte column under `position` in pane `id`'s C.
    fn c_hit(
        &self,
        id: PaneId,
        position: Point<Pixels>,
    ) -> Option<(Arc<CDocument>, usize, usize, bool)> {
        let document = Arc::clone(self.document(self.layout.active(id)?)?);
        let state = self.panes.get(&id)?;
        let b = state.bounds.get();
        let x = f32::from(position.x - b.origin.x);
        let y = f32::from(position.y - b.origin.y);
        let on_bar = x > f32::from(b.size.width) - f32::from(self.z(SCROLLBAR));
        let row = self.row(self.settings.c_line_height);
        let line = state.c.scroll.anchor.line
            + crate::workspace::rows_in(y + state.c.scroll.anchor.offset + 1.0, row)
            - 1;
        let line = usize::try_from(line).ok()?;
        let text_x = (x - self.c_gutter(id, &document)).max(0.0) + state.c.side.x;
        let col = column(
            text_x - f32::from(self.z(PAD)),
            self.char_width.unwrap_or(8.0),
        );
        let text = document.line_text(line);
        let byte = text.char_indices().nth(col).map_or(text.len(), |(b, _)| b);
        Some((document, line, byte, on_bar))
    }

    fn c_down(
        &mut self,
        id: PaneId,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.close_peek();
        if self.sideways_down(id, e) {
            cx.notify();
            return;
        }
        if self.field.as_ref().is_some_and(|f| f.pane == id) {
            self.field = None;
        }
        if self.comment.as_ref().is_some_and(|c| c.pane == id) {
            self.comment = None;
        }
        // While a definition is edited in place the rows below it are
        // moved: a click outside it does nothing.
        if self.inline_struct.as_ref().is_some_and(|s| s.pane == id) {
            return;
        }
        if self.layout.focused() != id {
            self.focus_pane(id, window, cx);
        }
        let Some((document, line, byte, on_bar)) = self.c_hit(id, e.position) else {
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
        if line >= document.lines.len() {
            return;
        }
        let span = document.span_at(line, byte);
        // Ctrl+click or a middle click on a name (a function's, a
        // global's): what it names in a new tab.
        let named = span
            .filter(|&s| document.variable(s).is_none() && document.member(s).is_none())
            .and_then(|s| self.c_name_address(&document, s));
        if self.open_name(id, named, name_click(e, cx), window, cx) {
            return;
        }
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let at = TextPos::new(line, column_at(document.line_text(line), byte));
        let cursor = TextPos::new(state.c.line, state.c.column);
        let at = press_selection(&mut state.c.selection, &document, e, (at, cursor));
        state.c.line = at.line;
        state.c.column = at.column;
        state.c.span = span;
        if let Some(s) = span {
            let kind = document.spans.get(s).map(|s| s.kind);
            state.c.highlight = match (document.variable(s), kind) {
                (Some(v), _) => Some(CHighlight::Node(Node::Var(v))),
                (
                    None,
                    Some(
                        CTokenKind::Function
                        | CTokenKind::Local
                        | CTokenKind::Parameter
                        | CTokenKind::Global
                        | CTokenKind::Field
                        | CTokenKind::Macro
                        | CTokenKind::Number
                        | CTokenKind::String
                        | CTokenKind::Type
                        | CTokenKind::BuiltinType
                        | CTokenKind::Label,
                    ),
                ) => Some(CHighlight::Text(document.span_text(s).to_owned())),
                _ => None,
            };
            if e.click_count == 2
                && (document.variable(s).is_some() || document.member(s).is_some())
            {
                // The field covers the token: nothing stays selected.
                state.c.selection.clear(at);
                self.moved(id);
                if self.open_field(id, window, cx) {
                    // The pane takes focus on a mouse down after its
                    // listeners ran unless the default is prevented: it
                    // would take it back from the field just focused.
                    window.prevent_default();
                }
                return;
            }
            if e.click_count == 2
                && kind == Some(CTokenKind::Label)
                && self.follow_label(id, &document, s, cx)
            {
                return;
            }
            if e.click_count == 2
                && kind.is_some_and(CTokenKind::is_name)
                && document.variable(s).is_none()
                && document.member(s).is_none()
                && let Some(target) = self.c_name_address(&document, s)
            {
                self.jump(target, cx);
                return;
            }
        }
        self.moved(id);
        cx.notify();
    }

    /// The address the name `s` in `document` stands for: a function's
    /// as the C declares it, else whatever the listing knows by the name
    /// (a global's, a name the user gave).
    pub fn c_name_address(&self, document: &CDocument, s: usize) -> Option<u64> {
        document.function_address(s).or_else(|| {
            let session = self.session.as_ref()?;
            self.listing
                .as_ref()?
                .find(document.span_text(s), session.overlay())
        })
    }

    /// Goes to the label that the `goto` at span `s` of pane `id`'s C
    /// names, remembering where the user was (Back returns to the
    /// `goto`); whether `s` names one.
    pub fn follow_label(
        &mut self,
        id: PaneId,
        document: &CDocument,
        s: usize,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(label) = document.label_definition(s) else {
            return false;
        };
        let (Some(line), Some(span)) = (document.line_of_span(label), document.spans.get(label))
        else {
            return false;
        };
        let start = document.lines.get(line).map_or(0, |l| l.range.start);
        let at = TextPos::new(
            line,
            column_at(document.line_text(line), span.range.start - start),
        );
        let from = self.location();
        let linked = self.layout.pane(id).is_some_and(|p| p.synced);
        self.trails.of(id, linked).push(from);
        let rows = self.rows(id, self.settings.c_line_height);
        let Some(state) = self.panes.get_mut(&id) else {
            return true;
        };
        state.c.selection.clear(at);
        state.c.line = at.line;
        state.c.column = at.column;
        state.c.span = Some(label);
        state.c.highlight = Some(CHighlight::Text(document.span_text(label).to_owned()));
        state
            .c
            .scroll
            .anchor
            .reveal(line as u64, document.lines.len() as u64, rows, rows / 3);
        self.moved(id);
        cx.notify();
        true
    }

    /// A right click: the cursor to the token (as a single click), then
    /// its context menu; in the selection, the cursor and the selection
    /// stay.
    fn c_right(
        &mut self,
        id: PaneId,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some((document, line, byte, on_bar)) = self.c_hit(id, e.position) else {
            return;
        };
        if on_bar {
            return;
        }
        let at = TextPos::new(line, column_at(document.line_text(line), byte));
        if self
            .c_selection(id)
            .is_some_and(|(from, to)| from <= at && at < to)
        {
            if self.layout.focused() != id {
                self.focus_pane(id, window, cx);
            }
            self.open_context_menu(Surface::C, e.position, window, cx);
            return;
        }
        let click = MouseDownEvent {
            click_count: 1,
            ..e.clone()
        };
        self.c_down(id, &click, window, cx);
        self.open_context_menu(Surface::C, e.position, window, cx);
    }

    fn c_move(
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
        let hit = self.c_hit(id, e.position);
        if e.dragging()
            && let Some((document, line, byte, _)) = &hit
            && self.c_drag(id, document, *line, *byte)
        {
            cx.notify();
            return;
        }
        let span = hit
            .as_ref()
            .filter(|(_, _, _, on_bar)| !on_bar)
            .and_then(|(d, line, byte, _)| d.span_at(*line, *byte).map(|s| (Arc::clone(d), s)));
        let link = span.as_ref().map(|(d, s)| Link::C {
            function: d.function,
            view: d.view,
            span: *s,
            addresses: d.span_addresses(*s).to_vec(),
        });
        // A value the architecture leaves undefined peeks at the
        // instruction leaving it so, saying what, what each processor's
        // profile does there and what the run shown gave.
        let undefined = span.as_ref().and_then(|(d, s)| Some((d, d.undefined(*s)?)));
        let note = undefined.map(|(document, value)| self.undefined_note(document, value));
        let target = undefined.map(|(_, value)| value.address).or_else(|| {
            let (d, s) = span.as_ref()?;
            let kind = d.spans.get(*s)?.kind;
            if !kind.is_name() || d.variable(*s).is_some() {
                return None;
            }
            self.listing
                .as_ref()?
                .find(d.span_text(*s), self.session.as_ref()?.overlay())
        });
        if self.link != link {
            self.link = link;
            cx.notify();
        }
        if let Some((document, ..)) = &hit {
            let document = Arc::clone(document);
            let had = self.facts.card.is_some();
            self.hover_why(&document, span.as_ref().map(|(_, s)| *s), e.position);
            if had != self.facts.card.is_some() {
                cx.notify();
            }
        }
        self.hover_peek(target, note, e.position, window, cx);
    }

    /// The peek card's note on `value`, which `document` shows: its
    /// register and site, each processor profile's rule there (the
    /// setting's first), and what the run shown gave there.
    fn undefined_note(&self, document: &CDocument, value: UndefinedValue) -> String {
        let names = self.register_names();
        let what = value.register.and_then(|r| names.get(usize::from(r.0)));
        let declarations = self
            .session
            .as_ref()
            .and_then(|s| s.database())
            .and_then(binbun::Database::declarations);
        let site = value.site.and_then(|site| {
            let info = declarations?.site(site)?;
            Some((site, info.name))
        });
        let chosen = self.processor_profile();
        let run = self.run_value(document, value);
        undefined_note(
            what.map(String::as_str),
            site,
            chosen.as_deref(),
            run.as_ref()
                .map(|(profile, values)| RunValue { profile, values }),
        )
    }

    /// A drag from a press in pane `id`'s C onto byte `byte` of line `line`
    /// of `document`: the cursor follows it, the characters from where it
    /// was pressed selected; whether it was such a drag.
    fn c_drag(&mut self, id: PaneId, document: &CDocument, line: usize, byte: usize) -> bool {
        let Some(state) = self.panes.get_mut(&id) else {
            return false;
        };
        if !state.c.selection.pressed {
            return false;
        }
        // Below the last line: its end.
        let last = document.lines.len().saturating_sub(1);
        let text = document.line_text(line.min(last));
        let at = if line > last {
            TextPos::new(last, text.chars().count())
        } else {
            TextPos::new(line, column_at(text, byte))
        };
        if TextPos::new(state.c.line, state.c.column) == at {
            return true;
        }
        state.c.line = at.line;
        state.c.column = at.column;
        state.c.span = document.span_at(at.line, byte_at(text, at.column));
        self.moved(id);
        true
    }

    /// Finds the hidden checks of function `function`'s reading view by
    /// line, once its reading or exact document came (both are read), for
    /// [`Self::reveals_of`]; forgets them where the reading view hides
    /// none.
    pub fn find_reveals(&mut self, function: FunctionId) {
        let Some(session) = &self.session else {
            return;
        };
        let Some(reading) = session
            .document(function, View::Reading)
            .filter(|d| !d.assumed().is_empty())
            .cloned()
        else {
            self.facts.reveals.remove(&function);
            return;
        };
        let exact = session.document(function, View::Exact);
        let found = reading.reveals(reading.assumed(), exact.map(AsRef::as_ref));
        let found = FoundReveals {
            on: reading,
            by_line: Arc::new(found),
        };
        self.facts.reveals.insert(function, found);
    }

    /// The hidden checks of `document` by line: those found when it came
    /// ([`Self::find_reveals`]), else found now (none for a view that hides
    /// nothing).
    fn reveals_of(
        &self,
        document: &Arc<CDocument>,
        exact: Option<&CDocument>,
    ) -> Arc<BTreeMap<usize, Reveal>> {
        if document.assumed().is_empty() {
            return Arc::default();
        }
        match self.facts.reveals.get(&document.function) {
            Some(found) if Arc::ptr_eq(&found.on, document) => Arc::clone(&found.by_line),
            _ => Arc::new(document.reveals(document.assumed(), exact)),
        }
    }

    /// Opens the rename field on the variable or member under pane `id`'s
    /// C cursor; whether there was one.
    pub fn open_field(&mut self, id: PaneId, window: &mut Window, cx: &mut Context<Self>) -> bool {
        let Some(document) = self
            .layout
            .active(id)
            .and_then(|k| self.document(k))
            .cloned()
        else {
            return false;
        };
        let Some(span) = self.panes.get(&id).and_then(|s| s.c.span) else {
            return false;
        };
        let Some(field) = Field::open(&document, span) else {
            return false;
        };
        let default = field.default(&document).to_owned();
        let original = field.original.clone();
        let input = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(original)
                .placeholder(default)
        });
        let changes = cx.subscribe_in(
            &input,
            window,
            move |this, input, e: &InputEvent, window, cx| match e {
                InputEvent::Change => {
                    let text = input.read(cx).value().to_string();
                    if let Some(edit) = &mut this.field {
                        edit.field.text = text;
                        edit.error = false;
                    }
                    cx.notify();
                }
                InputEvent::PressEnter { .. } => this.commit_field(window, cx),
                InputEvent::Focus | InputEvent::Blur => {}
            },
        );
        // The caret after the name, nothing selected: typing edits the
        // name rather than replacing it.
        input.update(cx, |s, cx| {
            let end = s.value().len();
            s.set_selected_range(end..end, cx);
            s.focus(window, cx);
        });
        if let Some(state) = self.panes.get_mut(&id) {
            state.c.highlight = Some(match field.var() {
                Some(var) => CHighlight::Node(Node::Var(var)),
                None => CHighlight::Text(field.original.clone()),
            });
        }
        self.field = Some(FieldEdit {
            pane: id,
            field,
            input,
            error: false,
            _changes: changes,
        });
        cx.notify();
        true
    }

    /// Commits the rename field: the session renames the variable (prints
    /// again) or the member (the struct is edited and what uses it
    /// decompiled again); the cursor comes back to it. A member's name
    /// refused (another member's) keeps the field, marked.
    fn commit_field(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(edit) = self.field.take() else {
            return;
        };
        let id = edit.pane;
        let Some(document) = self
            .layout
            .active(id)
            .and_then(|k| self.document(k))
            .cloned()
        else {
            return;
        };
        match edit.field.commit() {
            Ok(name) if name.as_deref() == Some(edit.field.original.as_str()) => {}
            // A member has no default name to reset to.
            Ok(None) if edit.field.var().is_none() => {}
            Ok(name) => {
                self.clocks.rename = Some(std::time::Instant::now());
                let anchor = edit.field.anchor(name.as_deref());
                let done = match (&edit.field.named, self.session.as_mut()) {
                    (&Named::Var(var), Some(s)) => s.rename_variable(&document, var, name),
                    (Named::Member { key, .. }, Some(s)) => {
                        let renamed = MemberEdit::Rename(name.unwrap_or_default());
                        s.edit_member(key, &edit.field.original, &renamed)
                            .map_err(|error| error.message)
                    }
                    (_, None) => Ok(()),
                };
                if let Err(error) = done {
                    self.error = Some(error);
                    if edit.field.var().is_none() {
                        self.field = Some(FieldEdit {
                            error: true,
                            ..edit
                        });
                        cx.notify();
                        return;
                    }
                }
                if let Some(state) = self.panes.get_mut(&id) {
                    state.c.restore = Some((anchor, edit.field.ordinal));
                }
                self.renamed = Some(Renamed {
                    pane: id,
                    document,
                    field: edit.field,
                });
                self.pin_active(id);
                self.ensure_documents();
            }
            Err(_) => {
                self.field = Some(FieldEdit {
                    error: true,
                    ..edit
                });
                cx.notify();
                return;
            }
        }
        self.focus_pane(id, window, cx);
    }

    /// Pins pane `id`'s active tab (an edit pins a preview tab).
    pub fn pin_active(&mut self, id: PaneId) {
        if let Some(active) = self.layout.pane(id).map(|p| p.active) {
            self.layout.pin(id, active);
        }
    }

    /// The view pane `id`'s C is in.
    pub fn c_view_of(&self, id: PaneId) -> Option<View> {
        match self.layout.active(id)? {
            TabKind::C { view, .. } => Some(*view),
            TabKind::Listing
            | TabKind::Settings
            | TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => None,
        }
    }

    /// Where span `span` of pane `id`'s C is drawn: the window's
    /// coordinates of its bottom left corner (where a card about it goes).
    pub fn c_span_point(&self, id: PaneId, span: usize) -> Option<Point<Pixels>> {
        let document = self.document(self.layout.active(id)?)?;
        let state = self.panes.get(&id)?;
        let line = document.line_of_span(span)?;
        let start = document.lines.get(line)?.range.start;
        let before = document
            .text
            .get(start..document.spans.get(span)?.range.start)?;
        let row = self.row(self.settings.c_line_height);
        let b = state.bounds.get();
        let x = self.c_gutter(id, document)
            + f32::from(self.z(PAD))
            + f(before.chars().count() as u64) * self.char_width.unwrap_or(8.0);
        let rows = (line as u64).checked_sub(state.c.scroll.anchor.line)?;
        let y = f(rows + 1) * row - state.c.scroll.anchor.offset;
        Some(Point {
            x: b.origin.x + px(x),
            y: b.origin.y + px(y),
        })
    }
}

/// The runs of `runs` (which cover a text end to end) cut to the bytes
/// `start..end`.
fn runs_covering(runs: &[TextRun], start: usize, end: usize) -> Vec<TextRun> {
    let mut out = Vec::new();
    let mut at = 0;
    for run in runs {
        let (s, e) = (at, at + run.len);
        at = e;
        let (s, e) = (s.max(start), e.min(end));
        if s < e {
            let mut run = run.clone();
            run.len = e - s;
            out.push(run);
        }
    }
    out
}

/// A press `e` at `at` of `document`, the cursor at `cursor`, on
/// `selection`: a left press selects from there as dragged (with Shift,
/// from the cursor), the token (a double click), the line (a triple); any
/// other drops it. Where the cursor goes.
fn press_selection(
    selection: &mut Text,
    document: &CDocument,
    e: &MouseDownEvent,
    (at, cursor): (TextPos, TextPos),
) -> TextPos {
    match (e.button, e.click_count) {
        (MouseButton::Left, 2) => {
            let (from, to) = c_token(document, at);
            selection.anchor = Some(from);
            selection.pressed = false;
            to
        }
        (MouseButton::Left, 3) => {
            let (from, to) = c_line(document, at.line);
            selection.anchor = Some(to);
            selection.pressed = false;
            from
        }
        (MouseButton::Left, _) => {
            selection.press(at, cursor, e.modifiers.shift);
            at
        }
        _ => {
            selection.clear(cursor);
            at
        }
    }
}
