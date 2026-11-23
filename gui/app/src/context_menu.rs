//! The context menus (a right click on the C, the listing, the graph, the
//! map, the strings and cross-references): the commands of the registry
//! for what is under the pointer (`binbun_gui_view::context`), each with
//! its key and state as the menu bar shows it. The right click moves the
//! cursor to the clicked item first (a row's address becomes the menu's
//! subject), so the commands act on it; and what the commands themselves
//! need of the item under the cursor: its kind, its number (for the
//! number conversions), opening it in a new pane. Things that are no command of
//! the registry (a bookmark's, a chat message's, a post's) have menus of
//! their own items ([`OwnItem`]).

use std::rc::Rc;

use binbun_gui_view::CTokenKind;
use binbun_gui_view::NumberForm;
use binbun_gui_view::commands;
use binbun_gui_view::context::{self, Surface, Target};
use binbun_gui_view::layout::Axis;
use binbun_gui_view::listing::{Overlay, Role};
use binbun_gui_view::map::Kind;
use binbun_gui_view::number::{Radix, Written, parse, same};
use gpui_kit::component::menu::{PopupMenu, PopupMenuItem};
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, DismissEvent, Entity, Focusable, Pixels, Point, SharedString,
    Subscription, Window, anchored, deferred, div, px,
};

use crate::overlays::enum_label;
use crate::popup::{self, ItemOf, MARGIN};
use crate::theme::hsla;
use crate::workspace::{PickerKind, TabKind, Workspace};

/// An open context menu.
pub struct ContextMenu {
    /// Where it opened (the window's coordinates of the click).
    position: Point<Pixels>,
    /// The menu.
    popup: Entity<PopupMenu>,
    _sub: Subscription,
}

/// What an item of a menu of the window's own runs.
pub type Run = Rc<dyn Fn(&mut Workspace, &mut Window, &mut Context<Workspace>)>;

/// An item of a menu of the window's own.
pub struct OwnItem {
    /// Its title.
    pub label: SharedString,
    /// Whether it can run.
    pub enabled: bool,
    /// Whether it is checked (what is chosen now).
    pub checked: bool,
    /// Its keys, shown muted at its right.
    pub key: Option<String>,
    /// What it runs.
    pub run: Run,
}

impl OwnItem {
    /// `label`, running `run`.
    pub fn new(
        label: impl Into<SharedString>,
        run: impl Fn(&mut Workspace, &mut Window, &mut Context<Workspace>) + 'static,
    ) -> Self {
        Self {
            label: label.into(),
            enabled: true,
            checked: false,
            key: None,
            run: Rc::new(run),
        }
    }
}

impl Workspace {
    /// What is under the focused pane's cursor (or the menu's subject).
    pub fn cursor_target(&self) -> Target {
        if let Some(subject) = self.menu_subject {
            return self.address_target(subject);
        }
        let id = self.layout.focused();
        let (Some(state), Some(listing), Some(session)) = (
            self.panes.get(&id),
            self.listing.as_ref(),
            self.session.as_ref(),
        ) else {
            return Target::Line;
        };
        match self.layout.active(id) {
            Some(kind @ TabKind::C { .. }) => {
                let (Some(document), Some(s)) = (self.document(kind), state.c.span) else {
                    return Target::Line;
                };
                if document.variable(s).is_some() {
                    return Target::Variable;
                }
                if document.member(s).is_some() {
                    return Target::Member;
                }
                let kind = document.spans.get(s).map(|span| span.kind);
                if kind.is_some_and(CTokenKind::is_name) {
                    self.c_name_address(document, s)
                        .map_or(Target::Line, |a| self.address_target(a))
                } else if document.number(s).is_some() {
                    Target::Number
                } else {
                    Target::Line
                }
            }
            Some(TabKind::Listing) => {
                let Some(db) = session.database() else {
                    return Target::Line;
                };
                let rendered = listing.render(db, state.listing.cursor, session.overlay());
                let Some(token) = state.listing.token.and_then(|i| rendered.tokens.get(i)) else {
                    return Target::Line;
                };
                if matches!(
                    token.role,
                    Role::CodeName | Role::DataName | Role::ImportName
                ) {
                    token
                        .target
                        .map_or(Target::Line, |a| self.address_target(a))
                } else if token.role == Role::Number && parse(&token.text).is_some() {
                    Target::Number
                } else {
                    Target::Line
                }
            }
            Some(
                TabKind::Settings
                | TabKind::Strings
                | TabKind::Xrefs { .. }
                | TabKind::Struct(_)
                | TabKind::Found(_)
                | TabKind::Folder(_),
            )
            | None => Target::Line,
        }
    }

    /// A function's name if a function starts at `address`, else another
    /// name.
    fn address_target(&self, address: u64) -> Target {
        if self
            .functions
            .binary_search_by_key(&address, |&(entry, _)| entry)
            .is_ok()
        {
            Target::Function
        } else {
            Target::Name
        }
    }

    /// The number under the focused pane's cursor: an instruction it came
    /// from, and the number as written. A C literal has no provenance of
    /// its own: of its line's instructions, the one whose listing line
    /// writes the same number, else the first (the session writes a
    /// literal by its line's instructions). A C literal's sign is the `-`
    /// right before it, on either token ([`CDocument::number`]).
    /// A number an enumeration's form shows (its constants' names, in the
    /// C and the listing) is the binary's number it spells.
    ///
    /// [`CDocument::number`]: binbun_gui_view::cdoc::CDocument::number
    pub fn number_under_cursor(&self) -> Option<(u64, Written)> {
        if self.menu_subject.is_some() {
            return None;
        }
        let id = self.layout.focused();
        let state = self.panes.get(&id)?;
        let listing = self.listing.as_ref()?;
        let session = self.session.as_ref()?;
        let db = session.database()?;
        match self.layout.active(id)? {
            kind @ TabKind::C { .. } => {
                let document = self.document(kind)?;
                let s = state.c.span?;
                let Some((literal, written)) = document.number(s) else {
                    // An enumeration's names: the line's instruction
                    // whose number its form spells so.
                    let line = document.lines.get(document.line_of_span(s)?)?;
                    let shown = document.span_text(s);
                    let overlay = session.overlay();
                    return line.addresses.iter().find_map(|&address| {
                        let bare =
                            listing.render(db, listing.line_of(address), &Overlay::default());
                        bare.tokens
                            .iter()
                            .filter(|t| t.role == Role::Number)
                            .filter_map(|t| parse(&t.text))
                            .find(|&written| {
                                overlay
                                    .number(address, written.bits)
                                    .filter(|form| matches!(form, NumberForm::Enum(_)))
                                    .and_then(|form| overlay.spell(&form, written, Radix::C))
                                    .is_some_and(|spelled| spelled == shown)
                            })
                            .map(|written| (address, written))
                    });
                };
                let line = document.lines.get(document.line_of_span(literal)?)?;
                let writes = |address: u64| {
                    let rendered = listing.render(db, listing.line_of(address), session.overlay());
                    rendered.tokens.iter().any(|t| {
                        t.role == Role::Number
                            && parse(&t.text).is_some_and(|n| same(n.bits, written.bits))
                    })
                };
                let address = line
                    .addresses
                    .iter()
                    .copied()
                    .find(|&a| writes(a))
                    .or_else(|| line.addresses.first().copied())?;
                Some((address, written))
            }
            TabKind::Listing => {
                // As shown, else (an enumeration's names) as the binary
                // writes it.
                let k = state.listing.token?;
                let number = |overlay: &Overlay| {
                    let rendered = listing.render(db, state.listing.cursor, overlay);
                    let token = rendered.tokens.get(k)?;
                    (token.role == Role::Number)
                        .then(|| parse(&token.text))
                        .flatten()
                };
                let written = number(session.overlay()).or_else(|| number(&Overlay::default()))?;
                Some((listing.line(state.listing.cursor)?.address, written))
            }
            TabKind::Settings
            | TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => None,
        }
    }

    /// Writes the number under the cursor in `form` (`H`, `R`): in
    /// the listing and the C, saved with the edits, undoable.
    pub fn convert_number(&mut self, form: NumberForm) {
        let Some((address, written)) = self.number_under_cursor() else {
            return;
        };
        self.number_form_at(address, written, form);
    }

    /// Writes number `written` of the instruction at `address` in `form`
    /// (saved with the edits, undoable), the focused pane kept where it is.
    pub fn number_form_at(&mut self, address: u64, written: Written, form: NumberForm) {
        if let Some(session) = &mut self.session {
            session.number(address, written.bits, Some(form));
        }
        let id = self.layout.focused();
        self.pin_active(id);
        self.ensure_documents();
    }

    /// `M`: a picker of the enumerations (the type library's, the user's)
    /// with a constant equal to the number under the cursor, or flags it
    /// holds, each with how the number reads by it; the one picked is the
    /// number's form.
    pub fn open_enum_picker(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some((address, written)) = self.number_under_cursor() else {
            return;
        };
        let Some(session) = &self.session else {
            return;
        };
        self.enum_choices = session.enumerations_of(written);
        self.enum_choices
            .sort_by(|(a, _), (b, _)| enum_label(a).cmp(enum_label(b)));
        if self.enum_choices.is_empty() {
            self.error = Some(format!("No enum names {:#x}", written.bits));
            return;
        }
        self.enum_number = Some((address, written));
        self.open_picker(PickerKind::Enum, window, cx);
    }

    /// Opens what the name under the cursor names in a new pane on the
    /// right (the same view as the focused pane's, a code view), its
    /// cursor there; the other panes stay where they are.
    pub fn open_in_new_pane(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(target) = self.target_under_cursor() else {
            return;
        };
        let id = self.layout.focused();
        let content = match self.layout.active(id) {
            Some(kind @ (TabKind::Listing | TabKind::C { .. })) => kind.clone(),
            _ => TabKind::Listing,
        };
        if let Some(new) = self.layout.split(id, Axis::Row, content) {
            self.ensure_pane(new, cx);
            self.set_cursor(new, target, true);
            self.focus_pane(new, window, cx);
            self.ensure_documents();
        }
    }

    /// Opens the context menu of `surface` at `position` for what is under
    /// the cursor (or the menu's subject).
    pub fn open_context_menu(
        &mut self,
        surface: Surface,
        position: Point<Pixels>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.close_peek();
        self.facts.card = None;
        let target = self.cursor_target();
        let facts = self.facts();
        let selected = facts.selection;
        let focus = self
            .panes
            .get(&self.layout.focused())
            .map(|s| s.focus.clone());
        let keymap = Rc::new(self.keymap.clone());
        let muted = hsla(self.theme.text_muted);
        let popup = PopupMenu::build(window, cx, move |mut m, window, cx| {
            if let Some(focus) = focus {
                m = m.action_context(focus);
            }
            let item: ItemOf = Rc::new(move |c| {
                popup::command_item(context::title(surface, c, &facts), c, &keymap, muted)
                    .disabled(!commands::state(c, &facts).enabled)
            });
            let entries = context::menu(surface, target, selected);
            let m = popup::with_entries(m, &entries, &item, window, cx);
            popup::capped_anywhere(m, &entries, window).min_w(px(200.0))
        });
        self.show_menu(position, popup, window, cx);
    }

    /// Opens a menu of `items` at `position`.
    pub fn open_own_menu(
        &mut self,
        position: Point<Pixels>,
        items: Vec<OwnItem>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.close_peek();
        let this = cx.entity().downgrade();
        let muted = hsla(self.theme.text_muted);
        let popup = PopupMenu::build(window, cx, move |mut m, _, _| {
            for item in &items {
                let run = Rc::clone(&item.run);
                let this = this.clone();
                let entry = match item.key.clone() {
                    Some(key) => {
                        let label = item.label.clone();
                        PopupMenuItem::element(move |_, _| {
                            div()
                                .flex()
                                .w_full()
                                .gap_3()
                                .items_center()
                                .justify_between()
                                .child(label.clone())
                                .child(
                                    div()
                                        .flex_none()
                                        .text_xs()
                                        .text_color(muted)
                                        .child(key.clone()),
                                )
                        })
                    }
                    None => PopupMenuItem::new(item.label.clone()),
                };
                m = m.item(
                    entry
                        .checked(item.checked)
                        .disabled(!item.enabled)
                        .on_click(move |_, window, cx| {
                            let _ = this.update(cx, |this, cx| {
                                run(this, window, cx);
                                cx.notify();
                            });
                        }),
                );
            }
            m.min_w(px(200.0))
        });
        self.show_menu(position, popup, window, cx);
    }

    /// Shows `popup` at `position`, focused; closed, the focus goes back
    /// to the focused pane, unless what the menu ran took it (a field it
    /// opened, the comment's).
    fn show_menu(
        &mut self,
        position: Point<Pixels>,
        popup: Entity<PopupMenu>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let sub = cx.subscribe_in(
            &popup,
            window,
            |this, menu, _: &DismissEvent, window, cx| {
                // A command the menu ran has run by now (its dispatch comes
                // before the dismissal): the subject was for it alone.
                this.context_menu = None;
                this.menu_subject = None;
                this.menu_folder = None;
                let kept = window
                    .focused(cx)
                    .is_none_or(|f| menu.focus_handle(cx).contains(&f, window));
                if !this.about
                    && kept
                    && !this.files_and_folders.is_open()
                    && this.picker.is_none()
                    && this.prompt.is_none()
                    && this.field.is_none()
                {
                    let id = this.layout.focused();
                    this.focus_pane(id, window, cx);
                }
                cx.notify();
            },
        );
        popup.update(cx, |p, cx| {
            let handle = p.focus_handle(cx);
            window.focus(&handle, cx);
        });
        // The click that opened it must not hand the focus back to the
        // pane (GPUI focuses a focusable element under a press after its
        // listeners ran, unless the default is prevented).
        window.prevent_default();
        self.context_menu = Some(ContextMenu {
            position,
            popup,
            _sub: sub,
        });
        cx.notify();
    }

    /// A right click on the map's row `k`: the row selected, its address
    /// the menu's subject; a folder's (but the file's) menu opens it as a
    /// tab.
    pub fn map_context(
        &mut self,
        k: usize,
        position: Point<Pixels>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(sidebar) = &mut self.sidebar else {
            return;
        };
        sidebar.selected = k;
        let Some(node) = sidebar
            .rows
            .get(k)
            .and_then(|row| sidebar.map.node(row.node))
        else {
            cx.notify();
            return;
        };
        if node.kind.is_folder() && node.kind != Kind::File {
            self.menu_folder = Some(node.key.clone());
            self.open_context_menu(Surface::Folder, position, window, cx);
            return;
        }
        let Some(address) = node.address else {
            cx.notify();
            return;
        };
        if node.kind.is_bookmark() {
            let (kind, author, name) = (node.kind, node.author, node.name.clone());
            let items = self.bookmark_menu(kind, author, address, &name);
            self.open_own_menu(position, items, window, cx);
            return;
        }
        self.menu_subject = Some(address);
        self.open_context_menu(Surface::Row, position, window, cx);
    }

    /// The open context menu, at its click.
    pub fn render_context_menu(&self) -> Option<AnyElement> {
        let menu = self.context_menu.as_ref()?;
        Some(
            deferred(
                anchored()
                    .position(menu.position)
                    .snap_to_window_with_margin(px(MARGIN))
                    .child(div().occlude().child(menu.popup.clone())),
            )
            .with_priority(2)
            .into_any_element(),
        )
    }
}
