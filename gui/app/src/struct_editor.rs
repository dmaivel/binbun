//! The struct editor (the binary's types written as C): a tab
//! showing a struct or union as its C definition, coloured as the C view
//! colours it, each member's offset in the gutter beside its line, a row
//! of `??` where bytes no member uses are and the struct's size on its
//! last line. Enter or a double click edits it (a double click on a type's
//! name opens that type instead): the same C, the bytes no member uses
//! after a member then beside it (`+4`), checked by the
//! engine's parser as it is typed (the bytes at fault underlined, the
//! reason under the text); Esc goes back to showing it while nothing is
//! changed;
//! `Ctrl+S` applies it through the session (undoable): a synthesised
//! struct's user's version replaces it, a definition is the user's.
//! Where the focused C pane prints the struct's definition it is edited
//! there, in place ([`InlineStruct`]: Enter on the definition, `Y` on its
//! name, or any way of opening the editor): the same view model, the
//! gutter on the definition's lines, `Ctrl+S` or Enter on the closing
//! line applies, Esc cancels, and the cursor comes back to the struct.
//! Elsewhere (a struct the C does not print, a new struct) it is a tab:
//! opened from the map's Types folder, from Set type on a struct pointer
//! (`Ctrl+Enter` in the field), from the palette (Edit Struct, New
//! Struct) and the variable's context menu; a new one opens edited.
//! An enumeration is edited so too, as C with each constant's value
//! beside its line: New Enum, and Edit Enum (the one a number is shown
//! by, else one picked from the type library's and the user's).

use std::ops::Range;
use std::rc::Rc;

use binbun_gui_view::cdoc::{Anchor, CDocument};
use binbun_gui_view::commands::Command;
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::structedit::{
    Gutter, Row, StructEdit, StructTarget, new_enum, new_struct, next_widths, struct_key, tokens,
};
use binbun_gui_view::{CError, CTokenKind, MemberEdit, NumberForm, TypeLayout};
use gpui_kit::component::Sizable as _;
use gpui_kit::component::input::{
    Editor, EditorState, FoldRange, HighlightStyleResolver, InputEdit, InputEvent,
    InputHighlighter, Rope, TextDecoration, TextDecorationCollection,
};
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, App, Context, Entity, Focusable, HighlightStyle, Hsla, MouseButton, MouseDownEvent,
    SharedString, StyledText, Subscription, UnderlineStyle, Window, div, px,
};

use crate::highlight::{Highlight as _, runs};
use crate::listing_view::column;
use crate::overlays::enum_label;
use crate::panes::measured;
use crate::theme::{Theme, hsla, solid};
use crate::workspace::{PickerKind, TabKind, Workspace, f};

/// The gutter's offset column's width, in characters (`0018.3` and a
/// space).
const OFFSET: u64 = 7;
/// The hole column's width (a space and `+3.5`).
const HOLE: u64 = 5;
/// The gutter's width in characters while a definition is edited in place.
pub const GUTTER: u64 = OFFSET + HOLE + 1;
/// The C text's left margin after the gutter (logical pixels): the C
/// view's.
const PAD: f32 = 12.0;
/// How far right of its box's left edge the editor in place draws its
/// text (logical pixels): the box's border, the code editor's left
/// padding at its extra small size, and the margin of its gutter (no
/// line numbers, no folds).
const INSET: f32 = 1.0 + 4.0 + 6.0;

/// An open struct editor.
pub struct StructEditor {
    /// The C and what the parser says of it.
    pub edit: StructEdit,
    /// Whether it is edited (else shown).
    editing: bool,
    input: Entity<EditorState>,
    /// The theme the input's colours are made for.
    coloured: &'static Theme,
    /// The bytes at fault underlined.
    marks: TextDecorationCollection,
    _subs: [Subscription; 2],
}

/// A type's C coloured as the C view colours it ([`tokens`]), for an
/// editor of it.
struct TypeColours {
    tokens: Vec<(Range<usize>, CTokenKind)>,
    theme: &'static Theme,
}

impl InputHighlighter for TypeColours {
    fn language(&self) -> SharedString {
        "c".into()
    }

    fn update(
        &mut self,
        _edit: Option<InputEdit>,
        text: &Rope,
        _folding: bool,
        _window: &mut Window,
        _cx: &mut Context<EditorState>,
    ) {
        self.tokens = tokens(&text.to_string());
    }

    fn styles(
        &self,
        range: &Range<usize>,
        _resolver: &dyn HighlightStyleResolver,
    ) -> Vec<(Range<usize>, HighlightStyle)> {
        let theme = self.theme;
        runs(
            self.tokens
                .iter()
                .map(|(range, kind)| (range.clone(), theme.c_kind(*kind))),
            range,
        )
    }

    fn fold_ranges(&self, _text: &Rope) -> Vec<FoldRange> {
        Vec::new()
    }
}

/// Colours `input`'s C with `theme`'s colours.
fn colour(input: &Entity<EditorState>, theme: &'static Theme, cx: &mut App) {
    input.update(cx, |s, cx| {
        s.set_highlighter_factory(
            Rc::new(move |_: &str| {
                let colours: Box<dyn InputHighlighter> = Box::new(TypeColours {
                    tokens: Vec::new(),
                    theme,
                });
                Some(colours)
            }),
            cx,
        );
    });
}

/// A struct's definition open for editing in place in a C pane: the
/// struct editor's view model over the definition's lines.
pub struct InlineStruct {
    /// The pane.
    pub pane: PaneId,
    /// What the pane shows (it closes when that changes).
    shows: TabKind,
    /// The key of the struct whose definition it stands over, as printed.
    key: String,
    /// The C and what the parser says of it.
    pub edit: StructEdit,
    input: Entity<EditorState>,
    /// The bytes at fault underlined.
    marks: TextDecorationCollection,
    _subs: [Subscription; 2],
}

impl InlineStruct {
    /// The lines of `document` it stands over (the definition's), if
    /// `document` prints it.
    pub fn lines(&self, document: &CDocument) -> Option<Range<usize>> {
        document
            .definitions()
            .find(|&(of, _)| document.struct_key(of).as_deref() == Some(self.key.as_str()))
            .map(|(_, lines)| lines)
    }

    /// The rows it takes: its text's lines, and one for the reason while
    /// the C is refused.
    pub fn rows(&self) -> usize {
        self.edit.gutter().len() + usize::from(self.edit.error.is_some())
    }
}

impl Workspace {
    /// The struct editor's commands; whether `command` is one of them.
    pub fn struct_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        if command == Command::EditStruct {
            if let Some(target) = self
                .struct_key_at_cursor()
                .and_then(|key| self.struct_target(&key))
            {
                self.open_struct(&target, window, cx);
            }
            true
        } else if command == Command::NewStruct {
            if let Some(session) = self.session.as_ref() {
                let c = new_struct(&session.type_names());
                self.new_type(c, window, cx);
            }
            true
        } else if command == Command::NewEnum {
            if let Some(session) = self.session.as_ref() {
                let c = new_enum(&session.type_names());
                self.new_type(c, window, cx);
            }
            true
        } else if command == Command::EditEnum {
            self.edit_enum(window, cx);
            true
        } else if command == Command::Follow {
            // Enter on a struct shown in its tab: edit it; on a struct's
            // definition in the C: open it in place.
            let id = self.layout.focused();
            if self.edit_struct_tab(id, None, window, cx) {
                return true;
            }
            self.definition_at_cursor(false)
                .is_some_and(|key| self.open_struct_in_place(id, &key, window, cx))
        } else if command == Command::Data {
            self.cycle_member_width();
            true
        } else if command == Command::Xrefs {
            // On a type's tab: where it is used.
            self.uses_of_type(window, cx)
        } else {
            false
        }
    }

    /// The key of the type pane `id`'s tab shows (`struct pair`, a
    /// typedef's name), as last applied.
    pub fn struct_tab_key(&self, id: PaneId) -> Option<String> {
        let Some(TabKind::Struct(target)) = self.layout.active(id) else {
            return None;
        };
        let editor = self.struct_editor(target)?;
        match target {
            StructTarget::Definition(key) => Some(key.clone()),
            StructTarget::Synthesised { .. } | StructTarget::New(_) => editor
                .edit
                .layout
                .as_ref()
                .map(|layout| layout.key().to_owned()),
        }
    }

    /// `D` on a member (its use or its declaration): its type the next
    /// width its struct's layout holds (byte, word, dword, qword, round),
    /// as an edit of the struct, the cursor kept on it; why not, where no
    /// width holds.
    fn cycle_member_width(&mut self) {
        let id = self.layout.focused();
        let Some((key, name, ordinal)) = self.member_at_cursor(id) else {
            return;
        };
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let size = session
            .struct_c(&key)
            .and_then(|c| session.struct_layout(&c).ok())
            .and_then(|layout| layout.members.into_iter().find(|m| m.name == name))
            .map_or(0, |m| m.size);
        let mut refused = None;
        for ty in next_widths(size) {
            match session.edit_member(&key, &name, &MemberEdit::Resize(ty.to_owned())) {
                Ok(()) => {
                    refused = None;
                    break;
                }
                Err(error) => refused = refused.or(Some(error.message)),
            }
        }
        if let Some(why) = refused {
            self.error = Some(why);
            return;
        }
        if let Some(state) = self.panes.get_mut(&id) {
            state.c.restore = Some((Anchor::Member { key, name }, ordinal));
        }
        self.pin_active(id);
        self.ensure_documents();
    }

    /// The member pane `id`'s C cursor is on: its struct's key, its name,
    /// which of its occurrences.
    pub fn member_at_cursor(&self, id: PaneId) -> Option<(String, String, usize)> {
        let document = self.document(self.layout.active(id)?)?;
        let span = self.panes.get(&id)?.c.span?;
        let of = document.member(span)?;
        let name = document.span_text(span).to_owned();
        let ordinal = document
            .member_occurrences(of, &name)
            .position(|s| s == span)?;
        Some((document.struct_key(of)?, name, ordinal))
    }

    /// The key of the definition pane's C cursor is in (only on its first
    /// line, the keyword and name, if `header`).
    fn definition_at_cursor(&self, header: bool) -> Option<String> {
        let id = self.layout.focused();
        let kind @ TabKind::C { .. } = self.layout.active(id)? else {
            return None;
        };
        let line = self.panes.get(&id)?.c.line;
        let (key, lines) = self.document(kind)?.definition_at(line)?;
        (!header || line == lines.start).then_some(key)
    }

    /// `Y` on a struct's definition's first line: the definition opened in
    /// place; whether it was.
    pub fn open_struct_in_place_at_cursor(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let id = self.layout.focused();
        self.definition_at_cursor(true)
            .is_some_and(|key| self.open_struct_in_place(id, &key, window, cx))
    }

    /// Opens the definition of `key` that pane `id`'s C prints for editing
    /// in place; whether it prints it (and there is something to edit).
    fn open_struct_in_place(
        &mut self,
        id: PaneId,
        key: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(shows @ TabKind::C { .. }) = self.layout.active(id).cloned() else {
            return false;
        };
        let Some(document) = self.document(&shows).cloned() else {
            return false;
        };
        let Some((_, lines)) = document
            .definitions()
            .find(|&(of, _)| document.struct_key(of).as_deref() == Some(key))
        else {
            return false;
        };
        let Some(target) = self.struct_target(key) else {
            return false;
        };
        self.field = None;
        self.c_type = None;
        let c = document.lines_text(lines);
        let checked = self.check_struct(&c);
        let input = cx.new(|cx| {
            EditorState::new(window, cx)
                .line_number(false)
                .folding(false)
                .default_value(c.clone())
        });
        colour(&input, self.theme, cx);
        let marks = input.update(cx, |s, cx| s.create_decorations_collection(Vec::new(), cx));
        let changes = cx.subscribe_in(&input, window, |this, input, e: &InputEvent, _, cx| {
            if matches!(e, InputEvent::Change) {
                let text = input.read(cx).value().to_string();
                let checked = this.check_struct(&text);
                let color = hsla(this.theme.error);
                if let Some(inline) = &mut this.inline_struct {
                    inline.edit.checked(text, checked);
                    mark(&inline.edit, &inline.marks, color, cx);
                }
                cx.notify();
            }
        });
        let this = cx.weak_entity();
        let handle = window.window_handle();
        let keys = cx.intercept_keystrokes(move |event, window, cx| {
            if window.window_handle() != handle {
                return;
            }
            let keystroke = &event.keystroke;
            let plain = !(keystroke.modifiers.control
                || keystroke.modifiers.shift
                || keystroke.modifiers.alt
                || keystroke.modifiers.platform);
            if !plain || !matches!(keystroke.key.as_str(), "escape" | "enter") {
                return;
            }
            let taken = this
                .update(cx, |this, cx| {
                    let Some(inline) = &this.inline_struct else {
                        return false;
                    };
                    let state = inline.input.read(cx);
                    if !state.focus_handle(cx).is_focused(window) {
                        return false;
                    }
                    let line = usize::try_from(state.cursor_position().line).unwrap_or(0);
                    let last = inline.edit.text.split('\n').count().saturating_sub(1);
                    let pane = inline.pane;
                    if keystroke.key == "escape" {
                        this.close_struct_in_place(window, cx);
                        return true;
                    }
                    // Enter on the closing line applies; elsewhere it is
                    // a new line.
                    line == last && this.apply_inline_struct(pane, window, cx)
                })
                .unwrap_or(false);
            if taken {
                cx.stop_propagation();
            }
        });
        let edit = StructEdit::new(target, c, checked);
        mark(&edit, &marks, hsla(self.theme.error), cx);
        input.update(cx, |s, cx| s.focus(window, cx));
        self.inline_struct = Some(InlineStruct {
            pane: id,
            shows,
            key: key.to_owned(),
            edit,
            input,
            marks,
            _subs: [changes, keys],
        });
        self.pin_active(id);
        cx.notify();
        true
    }

    /// Esc: the definition edited in place is dropped, unapplied.
    pub fn close_struct_in_place(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(inline) = self.inline_struct.take() {
            self.focus_pane(inline.pane, window, cx);
            cx.notify();
        }
    }

    /// `Ctrl+S` or Enter on the closing line: the definition edited in
    /// place in pane `id` applied through the session (the C decompiled
    /// again where the struct is, the cursor back on it), or the refusal
    /// marked; whether pane `id` has one.
    fn apply_inline_struct(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(inline) = self.inline_struct.as_mut().filter(|s| s.pane == id) else {
            return false;
        };
        if !inline.edit.changed() {
            self.close_struct_in_place(window, cx);
            return true;
        }
        let Some(session) = self.session.as_mut() else {
            return true;
        };
        let text = inline.edit.text.clone();
        match session.apply_struct(&inline.edit.target, &text) {
            Ok(_) => {
                let key = inline
                    .edit
                    .layout
                    .as_ref()
                    .map_or_else(|| inline.key.clone(), |layout| layout.key().to_owned());
                self.inline_struct = None;
                if let Some(state) = self.panes.get_mut(&id) {
                    state.c.restore = Some((Anchor::Struct(key), 0));
                }
                self.refresh_sidebar();
                self.ensure_documents();
                self.focus_pane(id, window, cx);
            }
            Err(error) => {
                inline.edit.checked(text, Err(error));
                mark(&inline.edit, &inline.marks, hsla(self.theme.error), cx);
            }
        }
        cx.notify();
        true
    }

    /// The definition edited in place in pane `id` over `document`, if
    /// there is one: its lines and the rows it takes. One no longer shown
    /// (the pane shows something else, the definition is gone) is closed.
    pub fn inline_block(
        &mut self,
        id: PaneId,
        document: &CDocument,
    ) -> Option<(Range<usize>, usize)> {
        let inline = self.inline_struct.as_ref().filter(|s| s.pane == id)?;
        let lines = (self.layout.active(id) == Some(&inline.shows))
            .then(|| inline.lines(document))
            .flatten();
        if lines.is_none() {
            self.inline_struct = None;
        }
        let inline = self.inline_struct.as_ref()?;
        Some((lines?, inline.rows()))
    }

    /// The definition edited in place in pane `id`: its gutter (offsets,
    /// sizes, holes) left of the editor, both over the definition's lines
    /// from `top` (the first line's row), the editor `gutter` wide into
    /// the pane, the reason under it while the C is refused.
    pub fn render_inline_struct(
        &self,
        id: PaneId,
        top: f32,
        gutter: f32,
        row_h: f32,
    ) -> Option<AnyElement> {
        let theme = self.theme;
        let inline = self.inline_struct.as_ref().filter(|s| s.pane == id)?;
        let cw = self.char_width.unwrap_or(8.0);
        let error_line = inline.edit.error_line();
        let shown = inline.edit.gutter();
        let lines = shown.len();
        let rows: Vec<AnyElement> = shown
            .into_iter()
            .enumerate()
            .map(|(line, shown)| self.gutter_row(shown, error_line == Some(line), row_h, cw))
            .collect();
        let message = inline.edit.error.as_ref().map(|e| e.message.clone());
        let height = f(lines as u64) * row_h;
        let left = gutter + f32::from(self.z(PAD));
        Some(
            div()
                .absolute()
                .top(px(top))
                .left_0()
                .right_0()
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                .child(
                    div()
                        .absolute()
                        .top_0()
                        .left_0()
                        .w(px(gutter))
                        .pl(px(cw))
                        .flex()
                        .flex_col()
                        .children(rows),
                )
                .child(
                    div()
                        .absolute()
                        // The editor's rows and text where the lines'
                        // are: its box a border's width up and its text's
                        // inset left.
                        .top(px(-1.0))
                        .left(px(left - INSET))
                        .right(self.z(16.0))
                        .h(px(height + 2.0))
                        .border_1()
                        .rounded(px(2.0))
                        .border_color(hsla(if message.is_some() {
                            theme.error
                        } else {
                            theme.border_focused
                        }))
                        .bg(hsla(solid(theme.editor)))
                        .child(
                            Editor::new(&inline.input)
                                .appearance(false)
                                .bordered(false)
                                .xsmall()
                                .h_full()
                                .font_family(self.settings.code_font.clone())
                                .text_size(px(self.code_size()))
                                .line_height(px(row_h)),
                        ),
                )
                .when_some(message, |d, message| {
                    d.child(
                        div()
                            .absolute()
                            .top(px(height))
                            .left(px(left))
                            .h(px(row_h))
                            .text_color(hsla(theme.error))
                            .child(message),
                    )
                })
                .into_any_element(),
        )
    }

    /// The key of the struct under the focused C pane's cursor: a tag, or
    /// the struct a variable's type names.
    pub fn struct_key_at_cursor(&self) -> Option<String> {
        let id = self.layout.focused();
        let kind @ TabKind::C { .. } = self.layout.active(id)? else {
            return None;
        };
        let span = self.panes.get(&id)?.c.span?;
        struct_key(self.document(kind)?, span)
    }

    /// What editing the struct or union `key` edits: a synthesised struct
    /// of the table by that name, else a definition (the user's or the
    /// type library's), if there is one.
    pub fn struct_target(&self, key: &str) -> Option<StructTarget> {
        let session = self.session.as_ref()?;
        if let Some(listed) = session.synthesised()
            && let Some(found) = listed.iter().find(|s| s.key == key)
        {
            return Some(StructTarget::Synthesised {
                function: found.function,
                k: found.k,
            });
        }
        session
            .definition_text(key)
            .map(|_| StructTarget::Definition(key.to_owned()))
    }

    /// Opens (or shows again) the editor on `target` in the focused pane.
    pub fn open_struct(
        &mut self,
        target: &StructTarget,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let id = self.layout.focused();
        // Where the focused C prints the struct, in place.
        let key = match target {
            &StructTarget::Synthesised { function, k } => {
                self.session.as_ref().and_then(|session| {
                    let listed = session.synthesised()?;
                    let found = listed.iter().find(|s| s.function == function && s.k == k)?;
                    Some(found.key.clone())
                })
            }
            StructTarget::Definition(key) => Some(key.clone()),
            StructTarget::New(_) => None,
        };
        if let Some(key) = key
            && self.open_struct_in_place(id, &key, window, cx)
        {
            return;
        }
        if self.struct_editor(target).is_none() {
            let Some(session) = self.session.as_ref() else {
                return;
            };
            let c = match target {
                &StructTarget::Synthesised { function, k } => {
                    session.synthesised().and_then(|listed| {
                        listed
                            .iter()
                            .find(|s| s.function == function && s.k == k)
                            .map(|s| s.c.clone())
                    })
                }
                StructTarget::Definition(key) => session.definition_text(key),
                StructTarget::New(_) => None,
            };
            let Some(c) = c else {
                return;
            };
            self.add_struct_editor(target.clone(), c, window, cx);
        }
        self.show_struct_tab(target, window, cx);
    }

    /// Edit Enum: the editor on the enumeration the number under the
    /// cursor is shown by, else a picker of every enumeration (the type
    /// library's, the user's) to open it on.
    fn edit_enum(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let shown = self
            .number_under_cursor()
            .and_then(|(address, written)| session.overlay().number(address, written.bits));
        if let Some(NumberForm::Enum(name)) = shown {
            self.open_struct(&StructTarget::Definition(name), window, cx);
            return;
        }
        self.enum_choices = session
            .enumeration_names()
            .into_iter()
            .map(|name| (name, String::new()))
            .collect();
        self.enum_choices
            .sort_by(|(a, _), (b, _)| enum_label(a).cmp(enum_label(b)));
        self.open_picker(PickerKind::EditEnum, window, cx);
    }

    /// Opens the editor on a new struct or enumeration, defined as C `c`.
    fn new_type(&mut self, c: String, window: &mut Window, cx: &mut Context<Self>) {
        // One of the first `editors + 1` numbers is free.
        let n = (1..=u32::try_from(self.struct_editors.len()).unwrap_or(u32::MAX - 1) + 1)
            .find(|&n| self.struct_editor(&StructTarget::New(n)).is_none())
            .unwrap_or(1);
        let target = StructTarget::New(n);
        self.add_struct_editor(target.clone(), c, window, cx);
        self.show_struct_tab(&target, window, cx);
    }

    /// The editor on `target`, if open.
    fn struct_editor(&self, target: &StructTarget) -> Option<&StructEditor> {
        self.struct_editors
            .iter()
            .find(|e| e.edit.target == *target)
    }

    /// A new editor on `target`, defined as C `c` (editors whose tabs
    /// were closed are dropped).
    fn add_struct_editor(
        &mut self,
        target: StructTarget,
        c: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let shown: Vec<StructTarget> = self
            .layout
            .panes()
            .flat_map(|pane| pane.tabs.iter())
            .filter_map(|tab| match &tab.content {
                TabKind::Struct(target) => Some(target.clone()),
                TabKind::Listing
                | TabKind::C { .. }
                | TabKind::Settings
                | TabKind::Console
                | TabKind::Terminal(_)
                | TabKind::Strings
                | TabKind::Xrefs { .. }
                | TabKind::Found(_)
                | TabKind::Folder(_) => None,
            })
            .collect();
        self.struct_editors
            .retain(|e| shown.contains(&e.edit.target));
        let checked = self.check_struct(&c);
        let input = cx.new(|cx| {
            EditorState::new(window, cx)
                .line_number(false)
                .folding(false)
                .default_value(c.clone())
        });
        colour(&input, self.theme, cx);
        let marks = input.update(cx, |s, cx| s.create_decorations_collection(Vec::new(), cx));
        let changes = cx.subscribe_in(&input, window, |this, input, e: &InputEvent, _, cx| {
            if matches!(e, InputEvent::Change) {
                let text = input.read(cx).value().to_string();
                this.struct_text_changed(input, text, cx);
            }
        });
        // Esc while nothing is changed: shown again.
        let this = cx.weak_entity();
        let handle = window.window_handle();
        let watched = input.clone();
        let keys = cx.intercept_keystrokes(move |event, window, cx| {
            let keystroke = &event.keystroke;
            if window.window_handle() != handle
                || keystroke.key != "escape"
                || keystroke.modifiers.modified()
                || !watched.read(cx).focus_handle(cx).is_focused(window)
            {
                return;
            }
            let shown = this
                .update(cx, |this, cx| {
                    let id = this.layout.focused();
                    this.show_struct_again(id, window, cx)
                })
                .unwrap_or(false);
            if shown {
                cx.stop_propagation();
            }
        });
        let editor = StructEditor {
            editing: matches!(target, StructTarget::New(_)),
            edit: StructEdit::new(target, c, checked),
            input,
            coloured: self.theme,
            marks,
            _subs: [changes, keys],
        };
        mark(&editor.edit, &editor.marks, hsla(self.theme.error), cx);
        self.struct_editors.push(editor);
    }

    /// Shows `target`'s tab of the strip (opening it), focused: its editor
    /// while it is edited.
    fn show_struct_tab(
        &mut self,
        target: &StructTarget,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let id = self.open_tool_tab(TabKind::Struct(target.clone()), cx);
        match self.struct_editor(target) {
            Some(editor) if editor.editing => {
                let input = editor.input.clone();
                input.update(cx, |s, cx| s.focus(window, cx));
            }
            _ => self.focus_pane(id, window, cx),
        }
        cx.notify();
    }

    /// The struct shown in pane `id`'s tab edited, the caret at `at` (a
    /// line and a column; else where it was); whether the pane shows one
    /// not edited.
    fn edit_struct_tab(
        &mut self,
        id: PaneId,
        at: Option<(usize, usize)>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(TabKind::Struct(target)) = self.layout.active(id).cloned() else {
            return false;
        };
        let Some(editor) = self
            .struct_editors
            .iter_mut()
            .find(|e| e.edit.target == target && !e.editing)
        else {
            return false;
        };
        editor.editing = true;
        let input = editor.input.clone();
        input.update(cx, |s, cx| s.focus(window, cx));
        // The caret placed once the press that asked for it is handled:
        // the editor, drawn now, would otherwise take a double click's
        // second press as its own and select the word under it.
        if let Some((line, column)) = at {
            cx.defer_in(window, move |_, window, cx| {
                input.update(cx, |s, cx| {
                    let position = gpui_kit::component::input::Position::new(
                        u32::try_from(line).unwrap_or(u32::MAX),
                        u32::try_from(column).unwrap_or(u32::MAX),
                    );
                    s.set_cursor_position(position, window, cx);
                });
            });
        }
        self.pin_active(id);
        cx.notify();
        true
    }

    /// The struct edited in pane `id`'s tab shown again, if nothing in it
    /// is changed; whether it was.
    fn show_struct_again(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(TabKind::Struct(target)) = self.layout.active(id).cloned() else {
            return false;
        };
        let Some(editor) = self.struct_editors.iter_mut().find(|e| {
            e.edit.target == target
                && e.editing
                && !e.edit.changed()
                && !matches!(target, StructTarget::New(_))
        }) else {
            return false;
        };
        editor.editing = false;
        self.focus_pane(id, window, cx);
        cx.notify();
        true
    }

    /// What the session's parser says of C `c`.
    fn check_struct(&self, c: &str) -> Result<TypeLayout, CError> {
        match self.session.as_ref() {
            Some(session) => session.type_layout(c),
            None => Err(CError {
                message: String::new(),
                span: 0..0,
            }),
        }
    }

    /// The editor of `input` holds `text` now: checked again, its error
    /// marked.
    fn struct_text_changed(
        &mut self,
        input: &Entity<EditorState>,
        text: String,
        cx: &mut Context<Self>,
    ) {
        let checked = self.check_struct(&text);
        let Some(editor) = self.struct_editors.iter_mut().find(|e| e.input == *input) else {
            return;
        };
        editor.edit.checked(text, checked);
        mark(&editor.edit, &editor.marks, hsla(self.theme.error), cx);
        cx.notify();
    }

    /// `Ctrl+S` in the struct editor of pane `id` (a tab, or a definition
    /// edited in place): its C applied through the session (the C
    /// decompiled again where the struct is), or the refusal marked;
    /// whether pane `id` has one.
    pub fn apply_struct_tab(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        if self.apply_inline_struct(id, window, cx) {
            return true;
        }
        let Some(TabKind::Struct(target)) = self.layout.active(id).cloned() else {
            return false;
        };
        let Some(session) = self.session.as_mut() else {
            return true;
        };
        let Some(editor) = self
            .struct_editors
            .iter_mut()
            .find(|e| e.edit.target == target)
        else {
            return true;
        };
        if !editor.edit.changed() && !matches!(target, StructTarget::New(_)) {
            return true;
        }
        let text = editor.edit.text.clone();
        match session.apply_struct(&target, &text) {
            Ok(now) => {
                editor.edit.applied(now.clone());
                editor.editing = false;
                if let Some(TabKind::Struct(shown)) = self.layout.active_mut(id) {
                    *shown = now;
                }
                self.refresh_sidebar();
                self.ensure_documents();
                self.focus_pane(id, window, cx);
            }
            Err(error) => {
                editor.edit.checked(text, Err(error));
                mark(&editor.edit, &editor.marks, hsla(self.theme.error), cx);
            }
        }
        cx.notify();
        true
    }

    /// The tab label of the editor on `target`: the key it defines, a
    /// dot while it has changes not applied.
    pub fn struct_tab_label(&self, target: &StructTarget) -> String {
        let Some(editor) = self.struct_editor(target) else {
            return "struct".to_owned();
        };
        let key = editor.edit.layout.as_ref().map_or_else(
            || {
                let head = editor.edit.text.lines().next().unwrap_or_default();
                head.trim_end_matches(['{', ' ']).to_owned()
            },
            |layout| layout.key().to_owned(),
        );
        if editor.edit.changed() {
            format!("{key} \u{2022}")
        } else {
            key
        }
    }

    /// One line of the struct editor's gutter (`row_h` high, characters
    /// `cw` wide): the offset, the hole quieter and half a line down,
    /// between the member and what follows it; both in the error's colour
    /// on the error's line.
    fn gutter_row(&self, shown: Gutter, error: bool, row_h: f32, cw: f32) -> AnyElement {
        let theme = self.theme;
        let color = if error {
            theme.error
        } else {
            theme.line_number
        };
        div()
            .h(px(row_h))
            .flex_none()
            .flex()
            .flex_row()
            .whitespace_nowrap()
            .text_color(hsla(color))
            .child(
                div()
                    .flex_none()
                    .w(px(cw * f(OFFSET)))
                    .children(shown.offset),
            )
            .child(
                div()
                    .flex_none()
                    .w(px(cw * f(HOLE)))
                    .relative()
                    .top(px(row_h / 2.0))
                    .text_color(hsla(if error { color } else { theme.text_muted }))
                    .children(shown.hole),
            )
            .into_any_element()
    }

    /// Pane `id`'s struct tab: the struct shown, or edited (the layout's
    /// gutter beside the C, the reason under it while the C is refused).
    pub fn render_struct(&mut self, id: PaneId, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let Some(TabKind::Struct(target)) = self.layout.active(id).cloned() else {
            return div().into_any_element();
        };
        let Some(editor) = self
            .struct_editors
            .iter_mut()
            .find(|e| e.edit.target == target)
        else {
            return div()
                .size_full()
                .bg(hsla(theme.editor))
                .rounded_b(self.island_corner())
                .into_any_element();
        };
        if !std::ptr::eq(editor.coloured, theme) {
            editor.coloured = theme;
            colour(&editor.input, theme, cx);
        }
        if !editor.editing {
            return self.render_struct_shown(id, &target, cx);
        }
        let Some(editor) = self.struct_editor(&target) else {
            return div().into_any_element();
        };
        let row_h = self.row(self.settings.c_line_height);
        let cw = self.char_width.unwrap_or(8.0);
        let scroll = editor.input.read(cx).scroll_offset();
        let error_line = editor.edit.error_line();
        let gutter: Vec<AnyElement> = editor
            .edit
            .gutter()
            .into_iter()
            .enumerate()
            .map(|(line, shown)| self.gutter_row(shown, error_line == Some(line), row_h, cw))
            .collect();
        let message = editor.edit.error.as_ref().map(|e| e.message.clone());
        let input = editor.input.clone();
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(hsla(theme.editor))
            .rounded_b(self.island_corner())
            .font_family(self.settings.code_font.clone())
            .text_size(px(self.code_size()))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .flex_row()
                    .pt(self.z(4.0))
                    .child(
                        div()
                            .flex_none()
                            .w(px(cw * f(OFFSET + HOLE)) + self.z(8.0))
                            .pl(self.z(8.0))
                            .overflow_hidden()
                            .child(div().flex().flex_col().mt(scroll.y).children(gutter)),
                    )
                    .child(
                        div().flex_1().min_w_0().h_full().child(
                            Editor::new(&input)
                                .appearance(false)
                                .bordered(false)
                                .xsmall()
                                .h_full()
                                .font_family(self.settings.code_font.clone())
                                .text_size(px(self.code_size()))
                                .line_height(px(row_h)),
                        ),
                    ),
            )
            .when_some(message, |d, message| {
                d.child(
                    div()
                        .flex_none()
                        .px(self.z(8.0))
                        .py(self.z(4.0))
                        .border_t_1()
                        .border_color(hsla(theme.border))
                        .text_color(hsla(theme.error))
                        .child(message),
                )
            })
            .into_any_element()
    }

    /// The struct of `target` shown in pane `id`: each line coloured as
    /// the C view colours it beside its offset (the size on the closing
    /// line), a row of `??` where bytes no member uses are. A double click
    /// on a type's name opens that type; anywhere else it edits the
    /// struct, the caret where it was.
    fn render_struct_shown(
        &self,
        id: PaneId,
        target: &StructTarget,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let (Some(editor), Some(state)) = (self.struct_editor(target), self.panes.get(&id)) else {
            return div().into_any_element();
        };
        let row_h = self.row(self.settings.c_line_height);
        let cw = self.char_width.unwrap_or(8.0);
        // Where the editor has its gutter and draws its text, so editing
        // moves nothing: its box has no border here.
        let pad = INSET - 1.0;
        let gutter_w = cw * f(OFFSET + HOLE) + f32::from(self.z(8.0));
        let text = editor.edit.text.as_str();
        let lines: Vec<&str> = text.split('\n').collect();
        let starts: Vec<usize> = lines
            .iter()
            .scan(0, |at, line| {
                let start = *at;
                *at += line.len() + 1;
                Some(start)
            })
            .collect();
        let coloured = tokens(text);
        let mut indent = 0;
        let rows: Vec<AnyElement> = editor
            .edit
            .rows()
            .into_iter()
            .map(|row| {
                let (offset, body, line) = match row {
                    Row::Line { line, offset } => {
                        let shown = lines.get(line).copied().unwrap_or_default();
                        let start = starts.get(line).copied().unwrap_or(0);
                        indent = shown.len() - shown.trim_start().len();
                        (
                            offset,
                            self.coloured_line(shown, start, &coloured),
                            Some(line),
                        )
                    }
                    Row::Hole { offset, bits } => {
                        let body = div()
                            .pl(px(cw * f(indent as u64)))
                            .text_color(hsla(theme.text_muted))
                            .child(Row::hole_text(bits))
                            .into_any_element();
                        (Some(offset), body, None)
                    }
                };
                div()
                    .h(px(row_h))
                    .flex()
                    .flex_row()
                    .whitespace_nowrap()
                    .child(
                        div()
                            .flex_none()
                            .w(px(gutter_w))
                            .pl(self.z(8.0))
                            .text_color(hsla(theme.line_number))
                            .children(offset),
                    )
                    .child(div().pl(px(pad)).child(body))
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                            if e.click_count == 2 {
                                let left = this
                                    .panes
                                    .get(&id)
                                    .map_or(0.0, |s| f32::from(s.bounds.get().origin.x));
                                let x = f32::from(e.position.x) - left - gutter_w - pad;
                                let at = line.map(|line| (line, column(x, cw)));
                                this.struct_shown_double_click(id, at, window, cx);
                            }
                        }),
                    )
                    .into_any_element()
            })
            .collect();
        let bounds = Rc::clone(&state.bounds);
        div()
            .id(("struct-shown", id.0))
            .key_context("Code")
            .track_focus(&state.focus)
            .size_full()
            .relative()
            .overflow_y_scroll()
            .bg(hsla(theme.editor))
            .rounded_b(self.island_corner())
            .font_family(self.settings.code_font.clone())
            .font_features(self.font_features())
            .text_size(px(self.code_size()))
            .line_height(px(row_h))
            .text_color(hsla(theme.editor_foreground))
            .child(measured(bounds).absolute().size_full())
            .child(div().pt(self.z(4.0)).flex().flex_col().children(rows))
            .into_any_element()
    }

    /// Line `shown` of a type's C, starting at byte `start` of it,
    /// coloured by the text's `tokens`.
    fn coloured_line(
        &self,
        shown: &str,
        start: usize,
        tokens: &[(Range<usize>, CTokenKind)],
    ) -> AnyElement {
        let theme = self.theme;
        let end = start + shown.len();
        let highlights = tokens
            .iter()
            .filter(|(r, _)| r.start >= start && r.end <= end)
            .map(|(r, kind)| {
                let style = HighlightStyle {
                    color: Some(hsla(theme.c_kind(*kind))),
                    ..HighlightStyle::default()
                };
                (r.start - start..r.end - start, style)
            });
        StyledText::new(shown.to_owned())
            .with_highlights(highlights)
            .into_any_element()
    }

    /// A double click on the struct shown in pane `id`, at a line and a
    /// column of its text (none on a row of unused bytes): the type whose
    /// name is there opened, else the struct edited with the caret there.
    fn struct_shown_double_click(
        &mut self,
        id: PaneId,
        at: Option<(usize, usize)>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some((line, column)) = at
            && self.open_type_at(id, line, column, window, cx)
        {
            return;
        }
        self.edit_struct_tab(id, at, window, cx);
    }

    /// A double click at `column` of line `line` of the struct shown in
    /// pane `id`: the type whose name is there opened in a tab of its own
    /// (`struct x`, `union x`, a typedef); whether one was.
    fn open_type_at(
        &mut self,
        id: PaneId,
        line: usize,
        column: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(TabKind::Struct(target)) = self.layout.active(id).cloned() else {
            return false;
        };
        let Some(editor) = self.struct_editor(&target) else {
            return false;
        };
        let text = editor.edit.text.as_str();
        let start: usize = text.split('\n').take(line).map(|l| l.len() + 1).sum();
        let shown = text.split('\n').nth(line).unwrap_or_default();
        let at = start
            + shown
                .char_indices()
                .nth(column)
                .map_or(shown.len(), |(b, _)| b);
        let all = tokens(text);
        let Some(index) = all
            .iter()
            .position(|(r, kind)| *kind == CTokenKind::Type && r.contains(&at))
        else {
            return false;
        };
        let name = all.get(index).and_then(|(r, _)| text.get(r.clone()));
        let tag = index
            .checked_sub(1)
            .and_then(|k| all.get(k))
            .and_then(|(r, _)| text.get(r.clone()))
            .filter(|w| matches!(*w, "struct" | "union" | "enum"));
        let Some(name) = name else {
            return false;
        };
        let key = tag.map_or_else(|| name.to_owned(), |tag| format!("{tag} {name}"));
        let own = editor
            .edit
            .layout
            .as_ref()
            .is_some_and(|layout| layout.key() == key);
        let Some(found) = self.struct_target(&key).filter(|_| !own) else {
            return false;
        };
        self.open_struct(&found, window, cx);
        true
    }
}

/// The error of `edit` marked in its editor's text: the bytes at fault
/// underlined in `color` (as the Set type field marks them) through the
/// editor's decorations `marks`, or the mark cleared. (The editor's own
/// diagnostics are drawn only with a syntax highlighter, which it has
/// not here.)
fn mark(edit: &StructEdit, marks: &TextDecorationCollection, color: Hsla, cx: &mut App) {
    let underline = HighlightStyle {
        underline: Some(UnderlineStyle {
            color: Some(color),
            thickness: px(2.0),
            wavy: false,
        }),
        ..HighlightStyle::default()
    };
    let decorations = edit
        .error_bytes()
        .map(|bytes| TextDecoration::new(bytes, underline))
        .into_iter()
        .collect();
    marks.set(decorations, cx);
}
