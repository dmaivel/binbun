//! Set type (`Y`) in the C: an inline field over the type token (a
//! variable's, a parameter's, a global's, a member's; a function's whole
//! prototype on its name), C typed with completion of the known type
//! names that fit, the session's errors marked under it before anything
//! is committed; Enter commits through the session (undoable), Esc drops
//! it. On a struct's definition, `Y` opens the definition in place. The
//! same field sets a whole program global's type from its root row in the
//! hex view's structure tree, over the row's type.

use std::ops::Range;
use std::sync::Arc;

use binbun_gui_view::cdoc::Anchor;
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::session::Session;
use binbun_gui_view::settype::{Subject, TypeField, complete, completions, declared_name};
use binbun_gui_view::{CError, MemberEdit, Node, Typed, VarKind};
use gpui_kit::base::Input as FieldInput;
use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, Entity, MouseButton, Pixels, Point, Subscription, Window, div, point, px,
};

use crate::theme::{hsla, solid};
use crate::workspace::{CHighlight, TabKind, Workspace, f};

/// The completions shown at most.
const COMPLETIONS: usize = 8;
/// The completions checked at most as a word is typed (each is the C
/// parsed once).
const TRIES: usize = 48;
/// The C text's left margin after the gutter (logical pixels): the C
/// view's.
const PAD: f32 = 12.0;

/// Where a Set type field shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// Over its type in the pane's C; while its declaration is scrolled
    /// out of sight, at the cursor's line and the byte its token starts
    /// at, where the field opened.
    C(usize, usize),
    /// Over the selected row's type in the pane's hex structure tree.
    Tree,
    /// Over the cursor row's text in the pane's unified listing.
    Unified,
}

/// The open Set type field.
pub struct CTypeField {
    /// The pane.
    pub pane: PaneId,
    /// What it types and where.
    pub field: TypeField,
    /// Where it shows.
    pub place: Place,
    input: Entity<InputState>,
    /// What the session refuses in the text, and the bytes of the text
    /// at fault.
    error: Option<(String, Range<usize>)>,
    /// The names a type may be written with.
    names: Arc<Vec<String>>,
    /// The names completing the word typed.
    completions: Vec<String>,
    _subs: [Subscription; 2],
}

impl Workspace {
    /// `Y`: opens the type field on what pane's C cursor is on; whether
    /// there was something to type.
    pub fn open_c_type(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        if self.open_struct_in_place_at_cursor(window, cx) {
            return true;
        }
        let id = self.layout.focused();
        let Some(field) = self.type_field_at(id) else {
            return false;
        };
        let var = matches!(
            field.subject,
            Subject::Typed(Typed::Variable(_) | Typed::Global(_))
        )
        .then(|| {
            let span = self.panes.get(&id)?.c.span?;
            let document = self.layout.active(id).and_then(|k| self.document(k))?;
            document.variable(declared_name(document, span).unwrap_or(span))
        })
        .flatten();
        if let (Some(var), Some(state)) = (var, self.panes.get_mut(&id)) {
            state.c.highlight = Some(CHighlight::Node(Node::Var(var)));
        }
        let (line, start) = self
            .panes
            .get(&id)
            .and_then(|state| {
                let span = state.c.span?;
                let document = self.layout.active(id).and_then(|k| self.document(k))?;
                Some((state.c.line, document.spans.get(span)?.range.start))
            })
            .unwrap_or((field.line, field.range.start));
        self.open_type_input(id, field, Place::C(line, start), window, cx);
        true
    }

    /// Opens the Set type field `field` in pane `id`, shown at `place`.
    pub fn open_type_input(
        &mut self,
        id: PaneId,
        field: TypeField,
        place: Place,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let names = Arc::new(
            self.session
                .as_ref()
                .map(Session::type_names)
                .unwrap_or_default(),
        );
        let input = cx.new(|cx| InputState::new(window, cx).default_value(field.original.clone()));
        let changes =
            cx.subscribe_in(
                &input,
                window,
                |this, input, e: &InputEvent, window, cx| match e {
                    InputEvent::Change => {
                        let text = input.read(cx).value().to_string();
                        this.type_text_changed(text);
                        cx.notify();
                    }
                    InputEvent::PressEnter {
                        secondary: true, ..
                    } => this.edit_typed_struct(window, cx),
                    InputEvent::PressEnter { .. } => this.commit_c_type(window, cx),
                    InputEvent::Focus | InputEvent::Blur => {}
                },
            );
        let this = cx.weak_entity();
        let handle = window.window_handle();
        let escape = cx.intercept_keystrokes(move |event, window, cx| {
            if window.window_handle() != handle {
                return;
            }
            let key = event.keystroke.key.as_str();
            if !matches!(key, "escape" | "tab") {
                return;
            }
            let taken = this
                .update(cx, |this, cx| {
                    if this.c_type.is_none() {
                        return false;
                    }
                    if key == "tab" {
                        this.take_completion(window, cx)
                    } else {
                        this.close_c_type(window, cx);
                        true
                    }
                })
                .unwrap_or(false);
            if taken {
                cx.stop_propagation();
            }
        });
        input.update(cx, |s, cx| {
            s.select_all(window, cx);
            s.focus(window, cx);
        });
        self.c_type = Some(CTypeField {
            pane: id,
            field,
            place,
            input,
            error: None,
            names,
            completions: Vec::new(),
            _subs: [changes, escape],
        });
        cx.notify();
    }

    /// The field for what pane `id`'s C cursor is on: a variable's type, a
    /// parameter's (the prototype), a member's, a function's prototype on
    /// its name; on a declaration's type word, the field of the name it
    /// declares.
    fn type_field_at(&self, id: PaneId) -> Option<TypeField> {
        let kind @ TabKind::C { .. } = self.layout.active(id)? else {
            return None;
        };
        let document = self.document(kind)?;
        let span = self.panes.get(&id)?.c.span?;
        let span = declared_name(document, span).unwrap_or(span);
        let session = self.session.as_ref()?;
        if let Some(of) = document.member(span) {
            let c = session.struct_c(&document.struct_key(of)?)?;
            return TypeField::member(document, span, &c);
        }
        if let Some(var) = document.variable(span) {
            let l2 = &document.decompiled.as_ref()?.l2;
            return match l2.var(var)?.kind {
                VarKind::Parameter => {
                    TypeField::parameter(document, var, Typed::Prototype(document.entry))
                }
                VarKind::Global(address) => {
                    TypeField::variable(document, var, Typed::Global(address))
                }
                VarKind::Local | VarKind::Frame(_) => {
                    let typed = session.variable_typed(document, var).ok()?;
                    TypeField::variable(document, var, typed)
                }
                VarKind::Environment(_) => None,
            };
        }
        let name = document.span_text(span);
        let address = self.listing.as_ref()?.find(name, session.overlay())?;
        session.database()?.function_at(address)?;
        let line = TypeField::prototype_line(document, name)?;
        TypeField::prototype(document, line, Typed::Prototype(address))
    }

    /// The field's text is `text` now: the session's check of it, the
    /// completions of its last word that fit.
    fn type_text_changed(&mut self, text: String) {
        let Some(edit) = &mut self.c_type else {
            return;
        };
        edit.field.text = text;
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let mut probe = edit.field.clone();
        edit.completions = completions(&edit.names, &edit.field.text, COMPLETIONS, TRIES, |text| {
            text.clone_into(&mut probe.text);
            check(session, &probe).is_none()
        });
        edit.error = if edit.field.text.trim().is_empty() {
            None
        } else {
            check(session, &edit.field).map(|error| {
                let range = edit.field.error_range(&error);
                (error.message, range)
            })
        };
    }

    /// Tab: the first completion in place of the last word; whether there
    /// was one.
    fn take_completion(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        let Some((input, text)) = self.c_type.as_ref().and_then(|edit| {
            let first = edit.completions.first()?;
            Some((edit.input.clone(), complete(&edit.field.text, first)))
        }) else {
            return false;
        };
        input.update(cx, |s, cx| s.set_value(text.clone(), window, cx));
        self.type_text_changed(text);
        cx.notify();
        true
    }

    /// Enter: the session takes the type (the C is decompiled again where
    /// it reaches); refused, the field stays with the error.
    fn commit_c_type(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(edit) = &self.c_type else {
            return;
        };
        let pane = edit.pane;
        let place = edit.place;
        if !edit.field.changed() {
            self.close_c_type(window, cx);
            return;
        }
        let subject = edit.field.subject.clone();
        let subject_kept = subject.clone();
        let ordinal = self
            .member_at_cursor(pane)
            .map_or(0, |(_, _, ordinal)| ordinal);
        let c = edit.field.commit();
        let text = edit.field.text.trim().to_owned();
        let done = self.session.as_mut().map(|session| match subject {
            Subject::Typed(typed) => session.set_type(typed, c),
            // A member's type is never reset (its struct has no other).
            Subject::Member { .. } if text.is_empty() => Ok(()),
            Subject::Member { key, name } => session
                .edit_member(&key, &name, &MemberEdit::Retype(text))
                .map_err(|error| error.message),
        });
        if let Some(Err(message)) = done {
            if let Some(edit) = &mut self.c_type {
                let range = 0..edit.field.text.len();
                let shown = message
                    .rsplit_once(" (at ")
                    .map_or(message.as_str(), |(m, _)| m);
                edit.error = Some((shown.to_owned(), range));
            }
            cx.notify();
            return;
        }
        self.c_type = None;
        if matches!(place, Place::C(..)) {
            self.pin_active(pane);
        }
        if let Subject::Member { key, name } = subject_kept
            && let Some(state) = self.panes.get_mut(&pane)
        {
            // Back on the member's occurrence the cursor was on.
            state.c.restore = Some((Anchor::Member { key, name }, ordinal));
        }
        self.ensure_documents();
        self.focus_after_type(pane, place, window, cx);
    }

    /// Drops the field.
    pub fn close_c_type(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(edit) = self.c_type.take() {
            self.focus_after_type(edit.pane, edit.place, window, cx);
        }
    }

    /// The focus back where a type field at `place` in pane `pane` was
    /// opened from.
    fn focus_after_type(
        &mut self,
        pane: PaneId,
        place: Place,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match place {
            Place::C(..) | Place::Unified => self.focus_pane(pane, window, cx),
            Place::Tree => self.focus_hex_tree(pane, window, cx),
        }
    }

    /// `Ctrl+Enter`: the struct the field's type names (`struct pair *`)
    /// in the struct editor, the field dropped.
    fn edit_typed_struct(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(target) = self.c_type.as_ref().and_then(|edit| {
            let mut words = edit
                .field
                .text
                .split(|c: char| !(c.is_alphanumeric() || c == '_'));
            let key = loop {
                let word = words.next()?;
                if matches!(word, "struct" | "union") {
                    break format!("{word} {}", words.find(|w| !w.is_empty())?);
                }
            };
            self.struct_target(&key)
        }) else {
            return;
        };
        self.c_type = None;
        self.open_struct(&target, window, cx);
    }

    /// The field over its type in its pane's C, with the error under it
    /// and the completions below.
    #[expect(clippy::too_many_lines, reason = "the field's layers, in order")]
    pub fn render_c_type(&mut self) -> Option<AnyElement> {
        let theme = self.theme;
        let edit = self.c_type.as_ref()?;
        let (id, place) = (edit.pane, edit.place);
        let at = match place {
            Place::C(line, start) => {
                let Some(kind @ TabKind::C { .. }) = self.layout.active(id).cloned() else {
                    self.c_type = None;
                    return None;
                };
                self.c_type_at(id, &kind, (line, start))
            }
            Place::Tree => {
                if !self.shows_hex(id) {
                    self.c_type = None;
                    return None;
                }
                self.hex_type_at(id)
            }
            Place::Unified => {
                if !self.shows_unified(id) {
                    self.c_type = None;
                    return None;
                }
                self.unified_type_at(id)
            }
        };
        let (origin, row_h) = at?;
        let edit = self.c_type.as_ref()?;
        let cw = self.char_width.unwrap_or(8.0);
        // Over the type only: as wide as its text (and the caret after
        // it), not over the name after it.
        let chars = edit
            .field
            .text
            .chars()
            .count()
            .max(edit.field.original.chars().count());
        let width = f(chars as u64) * cw + 8.0;
        let error = edit.error.clone();
        // The bytes at fault underlined in the error's colour, under the
        // text (a character wide at its end).
        let marked = error.as_ref().map(|(_, range)| {
            let text = &edit.field.text;
            let chars = |to: usize| f(text.get(..to).map_or(0, |t| t.chars().count()) as u64);
            let start = chars(range.start.min(text.len()));
            let end = chars(range.end.min(text.len())).max(start + 1.0);
            div()
                .absolute()
                .bottom(px(1.0))
                .left(px(2.0 + start * cw))
                .w(px((end - start) * cw))
                .h(px(2.0))
                .bg(hsla(theme.error))
        });
        let completions: Vec<AnyElement> = edit
            .completions
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let name = name.clone();
                div()
                    .id(("type-completion", i))
                    .px(self.z(6.0))
                    .when(i == 0, |d| d.bg(hsla(theme.element_hover)))
                    .text_color(hsla(theme.text))
                    .hover(|d| d.bg(hsla(theme.element_hover)))
                    .child(name)
                    .into_any_element()
            })
            .collect();
        Some(
            div()
                .absolute()
                .top(origin.y)
                .left(origin.x - px(3.0))
                .min_w(px(width))
                .flex()
                .flex_col()
                .font_family(self.settings.code_font.clone())
                .text_size(px(self.code_size()))
                .bg(hsla(solid(theme.editor)))
                .border_1()
                .border_color(hsla(if error.is_some() {
                    theme.error
                } else {
                    theme.border_focused
                }))
                .rounded(px(2.0))
                .shadow_lg()
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                .child(
                    div()
                        .relative()
                        .h(px(row_h - 2.0))
                        // The input lays its line out at the line height
                        // it inherits: the box's inside, so the type sits
                        // where the line's text does.
                        .line_height(px(row_h - 2.0))
                        .px(px(2.0))
                        .text_color(hsla(theme.text))
                        .child(FieldInput::new(&edit.input))
                        .children(marked),
                )
                .when_some(error, |d, (message, _)| {
                    d.child(
                        div()
                            .px(px(2.0))
                            .pb(px(2.0))
                            .text_size(px(self.code_size() * 0.9))
                            .text_color(hsla(theme.error))
                            .child(message),
                    )
                })
                .when(!completions.is_empty(), |d| {
                    d.child(
                        div()
                            .border_t_1()
                            .border_color(hsla(theme.border))
                            .children(completions),
                    )
                })
                .into_any_element(),
        )
    }

    /// Where a field over the type in pane `id`'s C (`kind`) shows, in the
    /// window, and its line's height: over the type where it is in sight,
    /// else at `anchor` (the cursor's line and the byte its token starts
    /// at, where it opened); `None` with neither in sight.
    fn c_type_at(
        &self,
        id: PaneId,
        kind: &TabKind,
        anchor: (usize, usize),
    ) -> Option<(Point<Pixels>, f32)> {
        let field = &self.c_type.as_ref()?.field;
        let document = self.document(kind)?;
        let state = self.panes.get(&id)?;
        let origin = state.bounds.get().origin;
        let row_h = self.row(self.settings.c_line_height);
        let cw = self.char_width.unwrap_or(8.0);
        let first = state.c.scroll.anchor.line;
        let rows = self.rows(id, self.settings.c_line_height);
        let shown = |line: usize| (first..first + rows).contains(&(line as u64));
        let (line, start) = if shown(field.line) {
            (field.line, field.range.start)
        } else {
            anchor
        };
        if !shown(line) {
            return None;
        }
        let line = line as u64;
        let y = f(line - first) * row_h - state.c.scroll.anchor.offset;
        let line_start = document.lines.get(usize::try_from(line).ok()?)?.range.start;
        let column = document.text.get(line_start..start)?.chars().count();
        let digits = document.lines.len().max(1).to_string().len().max(3);
        let gutter = cw * f(digits as u64 + 2);
        let x = gutter + f32::from(self.z(PAD)) + f(column as u64) * cw;
        Some((origin + point(px(x), px(y)), row_h))
    }
}

/// Why the session refuses `field`'s C (its text in its declaration, or
/// in its struct for a member), with the bytes at fault.
fn check(session: &Session, field: &TypeField) -> Option<CError> {
    match &field.subject {
        Subject::Typed(typed) => session.check_type(typed, &field.c()),
        Subject::Member { key, name } => {
            let retype = MemberEdit::Retype(field.text.clone());
            session.check_member(key, name, &retype, &field.c())
        }
    }
}
