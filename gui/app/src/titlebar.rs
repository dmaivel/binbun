//! The title bar, one row of the interface font (32 px at 13 px): the menu
//! bar (built from the command registry: every item's keys, states and
//! checks are the registry's), a quiet command center in place of the
//! window title (the file and the cursor's function, plain text, a faint
//! field on hover; a click opens go anywhere), the shared session's
//! participants (their avatars: a click follows them), and the window
//! controls when the platform
//! wants client-side decorations (GPUI Kit's title bar draws them, moves
//! the window on a drag and maximises it on a double click). On macOS the
//! menus are the native application menu instead. Either way the
//! registry's submenus are submenus.

use std::rc::Rc;

use binbun_gui_view::commands::{self, Command, Menu};
use binbun_gui_view::session::Session;
use gpui_kit::component::TitleBar;
use gpui_kit::component::menu::PopupMenu;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, DismissEvent, Entity, Focusable, KeyDownEvent, ModifiersChangedEvent,
    MouseButton, SharedString, Window, anchored, deferred, div, px,
};

use crate::collab::Tab;
use crate::popup::{self, ItemOf};
use crate::right_dock::Panel;
use crate::theme::hsla;
use crate::workspace::{OpenMenu, TITLE_PAD, Workspace, titled_file};

/// A menu title's height (logical).
const MENU_TITLE: f32 = 22.0;

impl Workspace {
    /// Opens `menu`'s popup under its title.
    pub fn open_menu(&mut self, menu: Menu, window: &mut Window, cx: &mut Context<Self>) {
        let facts = self.facts();
        // Undo names the agent's change it would undo.
        let undo =
            commands::undo_title(self.session.as_ref().and_then(Session::next_undo).as_ref());
        // Below the title bar (`menu_title` puts the popup's top there).
        let top = self.bar(TITLE_PAD);
        // The menu's actions go where the focus returns: the start page or
        // the focused pane.
        let focus = if self.shows_start() {
            Some(self.start_focus.clone())
        } else {
            self.panes
                .get(&self.layout.focused())
                .map(|s| s.focus.clone())
        };
        let keymap = Rc::new(self.keymap.clone());
        let muted = hsla(self.theme.text_muted);
        let popup = PopupMenu::build(window, cx, move |mut m, window, cx| {
            if let Some(focus) = focus {
                m = m.action_context(focus);
            }
            let item: ItemOf = Rc::new(move |c| {
                let state = commands::state(c, &facts);
                let title = match &undo {
                    Some(undo) if c == Command::Undo => undo.clone().into(),
                    _ => SharedString::from(commands::title(c, &facts)),
                };
                popup::command_item(title, c, &keymap, muted)
                    .disabled(!state.enabled)
                    .checked(state.checked.unwrap_or(false))
            });
            let entries = commands::menu_for(menu, &facts);
            let m = popup::with_entries(m, &entries, &item, window, cx);
            popup::capped(m, &entries, window, top).min_w(px(240.0))
        });
        let sub = cx.subscribe_in(&popup, window, |this, _, _: &DismissEvent, window, cx| {
            this.menu = None;
            // An overlay the menu opened keeps the focus it took.
            if this.about || this.files_and_folders.is_open() {
                window.focus(&this.overlay_focus, cx);
            } else if this.picker.is_none() && this.prompt.is_none() && this.field.is_none() {
                let id = this.layout.focused();
                this.focus_pane(id, window, cx);
            }
        });
        popup.update(cx, |p, cx| {
            let handle = p.focus_handle(cx);
            window.focus(&handle, cx);
        });
        self.menu = Some(OpenMenu {
            menu,
            popup,
            _sub: sub,
        });
        cx.notify();
    }

    /// The menu left or right of the open one (arrows in a menu).
    pub fn neighbour_menu(&mut self, right: bool, window: &mut Window, cx: &mut Context<Self>) {
        let Some(open) = self.menu.as_ref().map(|m| m.menu) else {
            return;
        };
        let all = Menu::ALL;
        let i = all.iter().position(|m| *m == open).unwrap_or(0);
        let next = if right {
            (i + 1) % all.len()
        } else {
            (i + all.len() - 1) % all.len()
        };
        if let Some(&menu) = all.get(next) {
            self.open_menu(menu, window, cx);
        }
    }

    /// Alt+letter opens a menu (its title's first letter); a lone Alt tap
    /// opens the first. Whether the key was taken.
    pub fn menu_keys(
        &mut self,
        e: &KeyDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        self.alt_tap = false;
        if cfg!(target_os = "macos") {
            return false;
        }
        let m = e.keystroke.modifiers;
        if !m.alt || m.control || m.shift || m.platform {
            return false;
        }
        let menu = Menu::ALL.into_iter().find(|menu| {
            menu.title()
                .chars()
                .next()
                .is_some_and(|c| c.to_ascii_lowercase().to_string() == e.keystroke.key)
        });
        match menu {
            Some(menu) => {
                self.open_menu(menu, window, cx);
                true
            }
            None => false,
        }
    }

    /// Tracks a lone Alt tap, and Ctrl (the chat's word links).
    pub fn alt_changed(
        &mut self,
        e: &ModifiersChangedEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let m = e.modifiers;
        // Ctrl draws the chat's ordinary words that are names as links.
        if self.right_dock.is_open(Panel::Session(Tab::Chat)) {
            cx.notify();
        }
        let only_alt = m.alt && !m.control && !m.shift && !m.platform;
        if only_alt {
            self.alt_tap = true;
        } else if self.alt_tap && !m.modified() {
            self.alt_tap = false;
            if self.menu.is_none() && !cfg!(target_os = "macos") {
                self.open_menu(Menu::File, window, cx);
            }
        } else {
            self.alt_tap = false;
        }
    }

    /// The title bar.
    pub fn render_titlebar(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let mut menus = div().flex().flex_none().items_center().h_full();
        if !cfg!(target_os = "macos") {
            for menu in Menu::ALL {
                let open = self
                    .menu
                    .as_ref()
                    .filter(|m| m.menu == menu)
                    .map(|m| m.popup.clone());
                menus = menus.child(self.menu_title(menu, open, cx));
            }
        }
        let avatars = self.collab_titlebar(cx);
        // The command center is centred on the window, as macOS's titles:
        // the two sides share what is left equally (each at least
        // as wide as its content), so the title moves off the centre only
        // as far as the menus or the right side push it, and is cut with an
        // ellipsis before it would overlap them.
        TitleBar::new()
            .h(self.bar(TITLE_PAD))
            .pl(self.z(4.0))
            // Its items centred on the bar as drawn, its bottom line in it.
            .pt(px(1.0))
            .bg(hsla(theme.background))
            .border_color(hsla(theme.border))
            .child(
                div()
                    .flex()
                    .items_center()
                    .w_full()
                    .h_full()
                    .child(div().flex_1().h_full().flex().items_center().child(menus))
                    .child(div().min_w_0().flex().child(self.command_center(cx)))
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .items_center()
                            .justify_end()
                            .gap(self.z(4.0))
                            .pr(self.z(8.0))
                            .children(avatars),
                    ),
            )
            .into_any_element()
    }

    fn menu_title(
        &self,
        menu: Menu,
        open: Option<Entity<PopupMenu>>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let is_open = open.is_some();
        let below = (self.ui_line() + TITLE_PAD + MENU_TITLE) / 2.0;
        div()
            .id(menu.title())
            .relative()
            .h(self.z(MENU_TITLE))
            .px(self.z(6.0))
            .flex()
            .items_center()
            .rounded(self.z(4.0))
            .text_color(hsla(theme.text))
            .when(is_open, |d| d.bg(hsla(theme.element_selected)))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, window, cx| {
                    window.prevent_default();
                    cx.stop_propagation();
                    if this.menu.as_ref().is_some_and(|m| m.menu == menu) {
                        this.menu = None;
                        cx.notify();
                    } else {
                        this.open_menu(menu, window, cx);
                    }
                }),
            )
            .on_hover(cx.listener(move |this, hovered: &bool, window, cx| {
                if *hovered && this.menu.as_ref().is_some_and(|m| m.menu != menu) {
                    this.open_menu(menu, window, cx);
                }
            }))
            .child(menu.title())
            .when_some(open, |d, popup| {
                d.child(deferred(
                    anchored()
                        .snap_to_window_with_margin(px(popup::MARGIN))
                        .child(div().occlude().mt(self.z(below)).child(popup)),
                ))
            })
            .into_any_element()
    }

    /// The command center: `file — function` (of a universal file, its
    /// slice after the file), plain at rest, a faint field on hover; a
    /// click opens go anywhere.
    fn command_center(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let Some(session) = &self.session else {
            return div().into_any_element();
        };
        let mut text = titled_file(session);
        if let Some(address) = self.current_address() {
            let place = self
                .listing
                .as_ref()
                .and_then(|l| {
                    let named = l.function_of(address).map_or(address, |(_, e)| e);
                    l.shown_name(named, session.overlay()).map(str::to_owned)
                })
                .unwrap_or_else(|| format!("{address:X}"));
            let place = self
                .demangled
                .get(&place)
                .and_then(Clone::clone)
                .unwrap_or(place);
            text = format!("{text} — {place}");
        }
        div()
            .id("command-center")
            .max_w(self.z(560.0))
            .min_w_0()
            .h(self.z(MENU_TITLE))
            .px(self.z(10.0))
            .flex()
            .items_center()
            .rounded(self.z(4.0))
            .overflow_hidden()
            .whitespace_nowrap()
            .text_ellipsis()
            .text_color(hsla(theme.text_muted))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_mouse_down(MouseButton::Left, |_, window, cx| {
                window.prevent_default();
                cx.stop_propagation();
            })
            .on_click(cx.listener(|this, _, window, cx| this.run(Command::GoAnywhere, window, cx)))
            .child(text)
            .into_any_element()
    }
}

/// The native application menu (macOS): the same registry, About and
/// Settings in the application's own menu, as the platform places them;
/// the submenus native submenus. Made whenever the keys are bound
/// ([`crate::actions::bind`]): an item shows the key bound to its action
/// then (Cmd's, `secondary-`).
#[cfg(target_os = "macos")]
pub fn native_menus(cx: &mut gpui_kit::App) {
    use binbun_gui_view::commands::Entry;
    use gpui_kit::{Menu as NativeMenu, MenuItem};

    use crate::actions::action;

    const APP_MENU: [Command; 2] = [Command::About, Command::Settings];

    fn item(c: Command) -> MenuItem {
        let facts = commands::Facts::default();
        MenuItem::Action {
            name: commands::lookup(c).map_or("", |i| i.title).into(),
            action: action(c),
            os_action: None,
            checked: commands::state(c, &facts).checked.unwrap_or(false),
            disabled: false,
        }
    }

    /// `entries` as native items, the application menu's left out (and a
    /// separator left without items before or after it).
    fn native_items(entries: &[Entry]) -> Vec<MenuItem> {
        let mut items: Vec<MenuItem> = Vec::new();
        for entry in entries {
            match entry {
                Entry::Separator => {
                    if !items.is_empty() && !matches!(items.last(), Some(MenuItem::Separator)) {
                        items.push(MenuItem::separator());
                    }
                }
                Entry::Command(c) if APP_MENU.contains(c) => {}
                Entry::Command(c) => items.push(item(*c)),
                Entry::Submenu { label, entries } => {
                    let sub = native_items(entries);
                    if !sub.is_empty() {
                        items.push(MenuItem::submenu(NativeMenu::new(*label).items(sub)));
                    }
                }
            }
        }
        if matches!(items.last(), Some(MenuItem::Separator)) {
            items.pop();
        }
        items
    }

    let own = NativeMenu::new("binbun").items([
        item(Command::About),
        MenuItem::separator(),
        item(Command::Settings),
    ]);
    let menus = Menu::ALL.into_iter().filter_map(|menu| {
        let items = native_items(&commands::menu(menu));
        (!items.is_empty()).then(|| NativeMenu::new(menu.title()).items(items))
    });
    cx.set_menus(core::iter::once(own).chain(menus));
}
