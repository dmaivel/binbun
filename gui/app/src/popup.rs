//! What the registry's popup menus share (the menu bar's, the context
//! menus, the feature map's): its entries as items, its submenus as GPUI
//! Kit's submenus; and a height capped at what the window has room for,
//! the rest scrolled, so no menu runs past the window, however small.
//!
//! An item shows its command's keys as the registry writes them
//! ([`commands::key_label`]): a sequence whole (`Ctrl-K S`), where GPUI
//! Kit's own key hint shows only its first keystroke.

use std::rc::Rc;

use binbun_gui_view::commands::{self, Binding, Command, Entry};
use gpui_kit::component::menu::{PopupMenu, PopupMenuItem};
use gpui_kit::prelude::*;
use gpui_kit::{Context, Hsla, Pixels, SharedString, Window, div, px};

use crate::actions::action;

/// The gap a menu keeps from the window's edges (logical).
pub const MARGIN: f32 = 8.0;
/// A menu's frame around its items (padding and border, both sides).
const FRAME: f32 = 10.0;
/// The least room a menu is given: a few items, however small the window.
const LEAST: f32 = 80.0;
/// An item's height in rems (GPUI Kit draws 26 px at a 16 px rem; a
/// little more, so a menu that fits is never taken to).
const ROW: f32 = 1.75;
/// A separator's height in rems (8 px at a 16 px rem).
const SEPARATOR: f32 = 0.5;
/// A submenu's least width (logical).
const SUBMENU_WIDTH: f32 = 200.0;

/// Makes a command's item.
pub type ItemOf = Rc<dyn Fn(Command) -> PopupMenuItem>;

/// Command `command`'s item, titled `title`, its keys under `keymap`
/// whole at its right in `muted`; it runs the command's action.
pub fn command_item(
    title: impl Into<SharedString>,
    command: Command,
    keymap: &[Binding],
    muted: Hsla,
) -> PopupMenuItem {
    let title = title.into();
    let key = commands::key_label(keymap, command);
    PopupMenuItem::element(move |_, _| {
        div()
            .flex()
            .w_full()
            .gap_3()
            .items_center()
            .justify_between()
            .child(title.clone())
            .children(
                key.clone()
                    .map(|key| div().flex_none().text_xs().text_color(muted).child(key)),
            )
    })
    .action(action(command))
}

/// The height a menu's items have below `top` (the window's y of the
/// menu's top edge), the margin and the frame left out.
pub fn room(window: &Window, top: Pixels) -> Pixels {
    (window.viewport_size().height - top - px(MARGIN + FRAME)).max(px(LEAST))
}

/// `m`, holding `entries`, capped at the window's height below `top`
/// (the window's y of its top edge) less the margin, scrolling past it.
/// A menu with room is left as it is: GPUI Kit's scrollable menu scrolls
/// by its padding even when all of it shows.
pub fn capped(m: PopupMenu, entries: &[Entry], window: &Window, top: Pixels) -> PopupMenu {
    let separators = entries.iter().filter(|e| **e == Entry::Separator).count();
    let rows = entries.len() - separators;
    #[expect(clippy::cast_precision_loss, reason = "a menu's entries")]
    let rems = ROW * rows as f32 + SEPARATOR * separators as f32;
    let room = room(window, top);
    if window.rem_size() * rems + px(FRAME) > room {
        m.max_h(room).scrollable(true)
    } else {
        m
    }
}

/// `m`, holding `entries`, capped at the window's whole height less the
/// margins: for a menu that moves into the window to fit (a context menu,
/// a submenu).
pub fn capped_anywhere(m: PopupMenu, entries: &[Entry], window: &Window) -> PopupMenu {
    capped(m, entries, window, px(MARGIN))
}

/// `m` with `entries` added: each command the item `item` makes of it,
/// each submenu a submenu of its own (capped too).
pub fn with_entries(
    mut m: PopupMenu,
    entries: &[Entry],
    item: &ItemOf,
    window: &mut Window,
    cx: &mut Context<PopupMenu>,
) -> PopupMenu {
    for entry in entries {
        m = match entry {
            Entry::Separator => m.separator(),
            Entry::Command(c) => m.item(item(*c)),
            Entry::Submenu { label, entries } => {
                let entries = entries.clone();
                let item = Rc::clone(item);
                m.submenu(*label, window, cx, move |sub, window, cx| {
                    let sub = with_entries(sub, &entries, &item, window, cx);
                    capped_anywhere(sub, &entries, window).min_w(px(SUBMENU_WIDTH))
                })
            }
        };
    }
    m
}
