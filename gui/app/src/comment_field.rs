//! The comment field in place: `;` and Comment open
//! it at the end of the cursor's line, in the listing at the comment
//! column after the operands (`; text`), in the C after the statement
//! (`// text`), in the graph on its line, the rows under it moved down as
//! it grows (in the graph its block grows, and what is below the block
//! moves down with the rows:
//! [`Graph::grown`](binbun_gui_view::graph::Graph::grown)). Enter commits,
//! Shift+Enter breaks the line, Escape or a click elsewhere cancels; an
//! empty comment removes it; a click in it moves its caret. The listing
//! lays a line under an item for each further line of its comment.

use std::sync::Arc;

use binbun_gui_view::comment::CommentField;
use binbun_gui_view::layout::PaneId;
use gpui_kit::base::Textarea;
use gpui_kit::component::input::{InputEvent, TextareaState};
use gpui_kit::prelude::*;
use gpui_kit::{AnyElement, Context, Entity, MouseButton, Subscription, Window, div, px};

use crate::theme::{hsla, solid};
use crate::workspace::{TabKind, Workspace, f};

/// The comment field open in a pane.
pub struct CommentEdit {
    /// The pane.
    pub pane: PaneId,
    /// The field.
    pub field: CommentField,
    /// The C line it is on (its comments' first), in a C pane.
    pub line: Option<usize>,
    /// The input.
    pub input: Entity<TextareaState>,
    pub(crate) _changes: Subscription,
}

impl Workspace {
    /// `;`: opens the comment field on the cursor's line of the focused
    /// pane: a listing's or its graph's (its item's address), a C's (the address
    /// [`CDocument::comment_address`](binbun_gui_view::cdoc::CDocument::comment_address)
    /// says).
    pub fn open_comment(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let id = self.layout.focused();
        let Some((field, line)) = self.comment_at_cursor(id) else {
            return;
        };
        self.close_overlays(window, cx);
        let text = field.text.clone();
        let input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .auto_grow(1, usize::MAX)
                .submit_on_enter(true)
                .default_value(text)
        });
        let changes =
            cx.subscribe_in(
                &input,
                window,
                |this, input, e: &InputEvent, window, cx| match e {
                    InputEvent::Change => {
                        let text = input.read(cx).value().to_string();
                        if let Some(edit) = &mut this.comment {
                            edit.field.text = text;
                        }
                        cx.notify();
                    }
                    // Shift+Enter has broken the line already.
                    InputEvent::PressEnter { shift: true, .. }
                    | InputEvent::Focus
                    | InputEvent::Blur => {}
                    InputEvent::PressEnter { .. } => this.commit_comment(window, cx),
                },
            );
        // The caret after the comment, nothing selected: typing adds to it
        // rather than replacing it.
        input.update(cx, |s, cx| {
            let end = s.value().len();
            s.set_selected_range(end..end, cx);
            s.focus(window, cx);
        });
        self.comment = Some(CommentEdit {
            pane: id,
            field,
            line,
            input,
            _changes: changes,
        });
        cx.notify();
    }

    /// The comment field for pane `id`'s cursor's line, with its C line.
    fn comment_at_cursor(&self, id: PaneId) -> Option<(CommentField, Option<usize>)> {
        let state = self.panes.get(&id)?;
        let session = self.session.as_ref()?;
        let comments = &session.overlay().comments;
        match self.layout.active(id)? {
            // The listing, or its graph (the same lines).
            TabKind::Listing if !state.hex.on && !state.calls.on => {
                let listing = self.listing.as_ref()?;
                let (address, ..) = listing.comment_place(
                    session.database()?,
                    state.listing.cursor,
                    session.overlay(),
                )?;
                Some((CommentField::open(address, comments), None))
            }
            kind @ TabKind::C { .. } if !state.ir.on => {
                let document = self.document(kind)?;
                let line = document.comment_owner(state.c.line);
                Some((CommentField::in_c(document, line, comments)?, Some(line)))
            }
            TabKind::Listing
            | TabKind::C { .. }
            | TabKind::Settings
            | TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => None,
        }
    }

    /// Commits the comment field: the comment is set (removed if empty),
    /// undoably; the documents showing it print again.
    fn commit_comment(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(edit) = self.comment.take() else {
            return;
        };
        if let Some(text) = edit.field.commit()
            && let Some(session) = self.session.as_mut()
        {
            if let Err(error) = session.comment(edit.field.address, text) {
                self.error = Some(error);
            }
            // The C printed again: the cursor back on the commented line.
            if edit.line.is_some()
                && let Some(state) = self.panes.get_mut(&edit.pane)
            {
                state.c.target = Some(edit.field.address);
            }
            self.lay_comments();
            self.pin_active(edit.pane);
            self.ensure_documents();
        }
        self.focus_pane(edit.pane, window, cx);
        cx.notify();
    }

    /// Lays the listing's lines for the comments as they are (a line under
    /// an item for each further line of its comment), each listing pane's
    /// cursor kept on its line and its viewport on the cursor's row.
    pub fn lay_comments(&mut self) {
        let (Some(listing), Some(session)) = (&mut self.listing, &self.session) else {
            return;
        };
        // Each cursor: its item, its line among the item's from its first
        // content line, its row in the viewport.
        let places: Vec<(PaneId, u64, i64, u64)> = self
            .panes
            .iter()
            .filter_map(|(&id, state)| {
                let cursor = state.listing.cursor;
                let address = listing.line(cursor)?.address;
                let content = listing.line_of(address);
                let from = i64::try_from(cursor).ok()? - i64::try_from(content).ok()?;
                Some((
                    id,
                    address,
                    from,
                    cursor.saturating_sub(state.listing.scroll.anchor.line),
                ))
            })
            .collect();
        if !Arc::make_mut(listing).set_comments(&session.overlay().comments) {
            return;
        }
        for (id, address, from, row) in places {
            let Some(state) = self.panes.get_mut(&id) else {
                continue;
            };
            let content = listing.line_of(address);
            let cursor = content
                .checked_add_signed(from)
                .filter(|&n| listing.line(n).is_some_and(|l| l.address == address))
                .unwrap_or(content);
            state.listing.cursor = cursor;
            state.listing.scroll.anchor.line = cursor.saturating_sub(row);
            state.listing.lit = None;
        }
    }

    /// The comment field's box for `edit` with its text's top left at `x`,
    /// `y` (the pane's pixels), rows `row_h` high: as many rows as the
    /// text has lines, each on its row's baseline, as wide as the widest.
    pub fn comment_box(&self, edit: &CommentEdit, x: f32, y: f32, row_h: f32) -> AnyElement {
        let theme = self.theme;
        let widest = edit
            .field
            .text
            .split('\n')
            .map(|line| {
                line.chars()
                    .map(|c| if c >= '\u{1100}' { 2 } else { 1 })
                    .sum::<usize>()
            })
            .max()
            .unwrap_or(0);
        let width = f(widest.max(1) as u64 + 2) * self.char_width.unwrap_or(8.0);
        let height = f(edit.field.lines() as u64) * row_h;
        // The border outside the text, so the lines sit on the rows'.
        div()
            .absolute()
            .left(px(x - 1.0))
            .top(px(y - 1.0))
            .w(px(width + 2.0))
            .h(px(height + 2.0))
            .overflow_hidden()
            .line_height(px(row_h))
            .bg(hsla(solid(theme.editor)))
            .border_1()
            .rounded(px(2.0))
            .border_color(hsla(theme.border_focused))
            .text_color(hsla(theme.text))
            // A click in the field moves its caret; the pane's own click
            // would close the field.
            .on_mouse_down(MouseButton::Left, |_, _, cx| {
                cx.stop_propagation();
            })
            .child(Textarea::new(&edit.input))
            .into_any_element()
    }
}
