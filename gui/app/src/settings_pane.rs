//! The settings pane (Ctrl+, or the palette), as dense as the chrome:
//! a narrow list of the groups on the left that jumps to each, and on the
//! right one search row over the settings in a column of bounded width,
//! each a row of the tree's height with its name left and its control
//! right: a small switch, a compact segmented choice, a small number box
//! (typed in, or stepped by the arrows and the wheel), a font dropdown
//! listing the bundled and installed families (monospace ones for code),
//! each in its own font, a program's field, a relay's segments (binbun,
//! n0, Custom) with a URL field for Custom. Enter or leaving a box or a
//! field sets what was typed in it. Search filters
//! both sides. A change applies at once and is
//! written to the settings file. No captions: a setting's name says it;
//! its one sentence is a tooltip. The Symbols group ends with the symbol
//! cache's path and size, quiet. The Agents group ends with each agent's
//! command as a field (a built-in's own as its placeholder; the user's
//! own with × to remove it) and a row adding one: a name and a command.

use std::rc::Rc;

use binbun_gui_view::agents;
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::settings::{CollabRelay, CustomAgent, Info, Kind, SETTINGS, Setting, matches};
use gpui_kit::assets::IconName;
use gpui_kit::component::Sizable as _;
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::menu::{PopupMenu, PopupMenuItem};
use gpui_kit::component::switch::Switch;
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, DismissEvent, ElementId, Entity, Focusable, KeyDownEvent, MouseButton,
    ScrollEvent, Window, anchored, deferred, div, font, px,
};

use crate::fonts::{BUNDLED_CODE, BUNDLED_UI};
use crate::icons::icon;
use crate::popup;
use crate::scrolling::{Area, wheel};
use crate::sidebar::tabular;
use crate::theme::{hsla, solid};
use crate::workspace::{ICON, PickerKind, ROW_PAD, Workspace};

/// A setting's row (logical): the tree's 22 and a little.
const ROW: f32 = 26.0;
/// A group heading's row, a little space above it included.
const HEADING: f32 = 30.0;
/// The space above the first group.
const TOP: f32 = 6.0;
/// The settings column's widest.
const COLUMN: f32 = 640.0;
/// The group list's width.
const NAV: f32 = 168.0;
/// A control's height.
const CONTROL: f32 = 20.0;
/// A number box's width.
const NUMBER: f32 = 56.0;
/// The relay's segments: the setting's value each sets (Custom: the URL
/// typed beside it).
const RELAYS: &[&str] = &["binbun", "n0", "Custom"];
/// The relay's URL field's width.
const RELAY_URL: f32 = 240.0;
/// The group the symbol cache's line ends (its path and size).
const SYMBOLS: &str = "Symbols";
/// The group the agents' rows end (each agent's command, and adding one).
pub const AGENTS: &str = "Agents";
/// An agent's command field's width, and the name field adding one.
const AGENT_COMMAND: f32 = 260.0;
const AGENT_NAME: f32 = 160.0;
/// The slot right of an agent's command: × for the user's own; Add.
const AGENT_END: f32 = 36.0;
/// The fields adding an agent.
const ADD_NAME: &str = "agent-add:name";
const ADD_COMMAND: &str = "agent-add:command";

/// What an agent's field does with the text typed (Enter, or leaving it:
/// `true` for Enter), and says what it then shows.
type FieldSet =
    Rc<dyn Fn(&mut Workspace, &str, bool, &mut Window, &mut Context<Workspace>) -> String>;

/// `n` on the nearest of `step`'s multiples.
fn on_step(n: f64, step: f64) -> f64 {
    (n / step).round() * step
}

/// A number box's number: whole numbers without a point, others with the
/// places they need (`0.85`, not `0.8500000000000001`).
fn shown(n: f64) -> String {
    let text = format!("{n:.6}");
    text.trim_end_matches('0').trim_end_matches('.').to_owned()
}

impl Workspace {
    /// The settings pane's search field (made the first time).
    pub fn settings_search(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Entity<InputState> {
        if let Some(search) = &self.settings_search {
            return search.clone();
        }
        let search = cx.new(|cx| InputState::new(window, cx));
        cx.subscribe_in(&search, window, |this, _, e: &InputEvent, _, cx| {
            if matches!(e, InputEvent::Change) {
                let panes: Vec<PaneId> = this.panes.keys().copied().collect();
                for id in panes {
                    this.reset_area(Area::Settings(id));
                }
            }
            cx.notify();
        })
        .detach();
        self.settings_search = Some(search.clone());
        search
    }

    /// The groups the search leaves, in order, each with the pixels its
    /// heading starts at in the settings column, and where the last ends
    /// (logical); the Agents group has `agent_rows` rows of its own.
    fn settings_groups(query: &str, agent_rows: usize) -> (Vec<(&'static str, f32)>, f32) {
        let own = |group: &str| match group {
            SYMBOLS => ROW,
            AGENTS => ROW * f32::from(u16::try_from(agent_rows).unwrap_or(u16::MAX)),
            _ => 0.0,
        };
        let mut groups: Vec<(&'static str, f32)> = Vec::new();
        let mut y = TOP;
        for info in SETTINGS.iter().filter(|i| matches(i, query)) {
            if groups.last().is_none_or(|(g, _)| *g != info.group) {
                if let Some((g, _)) = groups.last() {
                    y += own(g);
                }
                groups.push((info.group, y));
                y += HEADING;
            }
            y += ROW;
        }
        if let Some((g, _)) = groups.last() {
            y += own(g);
        }
        (groups, y)
    }

    /// Pane `id`'s settings.
    pub fn render_settings(
        &mut self,
        id: PaneId,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let search = self.settings_search(window, cx);
        let query = search.read(cx).value().to_string();
        let focus = self.panes.get(&id).map(|s| s.focus.clone());
        let agent_rows = agents::launchables(&self.settings).len() + 1;
        let (groups, end) = Self::settings_groups(&query, agent_rows);
        let scale = self.settings.ui_scale;
        let (at, viewport) = self.areas.get(&Area::Settings(id)).map_or((0.0, 0.0), |a| {
            (a.scroll.pixels() / scale, a.viewport.get() / scale)
        });
        self.jump_to_group(id, &groups, viewport > 0.0, window);
        // Room under the last group for its heading to scroll to the top,
        // as a click on any group's name scrolls its heading there.
        let last = groups.last().map_or(end, |&(_, top)| top);
        let bottom = (viewport - (end - last)).max(ROW);
        let current = groups
            .iter()
            .rev()
            .find(|(_, top)| *top <= at + 1.0)
            .or(groups.first())
            .map(|(g, _)| *g);
        let mut column = div()
            .flex()
            .flex_col()
            .w_full()
            .max_w(self.z(COLUMN))
            .pt(self.z(TOP))
            .pb(self.z(bottom));
        let mut group = "";
        for info in SETTINGS.iter().filter(|i| matches(i, &query)) {
            if info.group != group {
                if group == SYMBOLS {
                    column = column.child(self.symbol_cache_row(ROW, window, cx));
                }
                if group == AGENTS {
                    column = column.children(self.agent_setting_rows(window, cx));
                }
                group = info.group;
                column = column.child(
                    div()
                        .h(self.z(HEADING))
                        .pt(self.z(HEADING - ROW + 4.0))
                        .px(self.z(8.0))
                        .flex()
                        .items_center()
                        .text_color(hsla(theme.text_muted))
                        .child(group),
                );
            }
            column = column.child(self.setting_row(info, window, cx));
        }
        if group == SYMBOLS {
            column = column.child(self.symbol_cache_row(ROW, window, cx));
        }
        if group == AGENTS {
            column = column.children(self.agent_setting_rows(window, cx));
        }
        let content = self
            .scroll_area(Area::Settings(id), ("settings-rows", id.0), column, cx)
            .flex_1()
            .min_h_0()
            .px(self.z(12.0));
        let nav = self.settings_nav(id, &groups, current, cx);
        let search_row = div()
            .flex()
            .flex_none()
            .items_center()
            .gap(self.z(6.0))
            .h(self.z(self.ui_line() + ROW_PAD + 4.0))
            .px(self.z(12.0))
            .border_b_1()
            .border_color(hsla(theme.border_variant))
            .child(icon(IconName::Search, self.z(ICON), hsla(theme.text_muted)))
            .child(
                div()
                    .flex_1()
                    .max_w(self.z(COLUMN))
                    .child(Input::new(&search).appearance(false).small()),
            );
        div()
            .id(("settings", id.0))
            .size_full()
            .flex()
            .bg(hsla(theme.under(theme.editor)))
            .rounded_b(self.island_corner())
            .when_some(focus, |d, f| d.track_focus(&f))
            .child(nav)
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .bg(hsla(theme.editor))
                    .rounded_br(self.island_corner())
                    .child(search_row)
                    .child(content),
            )
            .into_any_element()
    }

    /// Customize… ([`Workspace::settings_jump`]): its group's heading at
    /// the top of pane `id`'s settings, once laid out: the frame after one
    /// drawn with the viewport known (`viewport_known`), whose room under
    /// the last group lets the heading reach the top.
    fn jump_to_group(
        &mut self,
        id: PaneId,
        groups: &[(&'static str, f32)],
        viewport_known: bool,
        window: &mut Window,
    ) {
        let Some((jump, primed)) = self.settings_jump else {
            return;
        };
        let Some(&(_, top)) = groups.iter().find(|(g, _)| *g == jump) else {
            self.settings_jump = None;
            return;
        };
        if primed {
            self.scroll_area_to(Area::Settings(id), top * self.settings.ui_scale);
            self.settings_jump = None;
        } else if viewport_known {
            self.settings_jump = Some((jump, true));
        }
        window.request_animation_frame();
    }

    /// The group list: a click scrolls its group's heading to the top.
    fn settings_nav(
        &mut self,
        id: PaneId,
        groups: &[(&'static str, f32)],
        current: Option<&'static str>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let row_h = self.row(self.ui_line() + ROW_PAD);
        let rows = groups.iter().map(|&(group, top)| {
            let on = current == Some(group);
            div()
                .id(group)
                .h(px(row_h))
                .px(self.z(12.0))
                .flex()
                .items_center()
                .text_color(hsla(if on { theme.text } else { theme.text_muted }))
                .when(on, |d| d.bg(hsla(theme.element_selected)))
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .on_click(cx.listener(move |this, _, _, cx| {
                    let y = top * this.settings.ui_scale;
                    this.scroll_area_to(Area::Settings(id), y);
                    cx.notify();
                }))
                .child(group)
        });
        let list = div().flex().flex_col().pt(self.z(6.0)).children(rows);
        self.scroll_area(Area::SettingsNav(id), ("settings-nav", id.0), list, cx)
            .w(self.z(NAV))
            .flex_none()
            .h_full()
            .border_r_1()
            .border_color(hsla(theme.border_variant))
            .bg(hsla(theme.panel))
            .rounded_bl(self.island_corner())
            .into_any_element()
    }

    fn setting_row(
        &mut self,
        info: &'static Info,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let key = info.key;
        let tooltip = info.tooltip;
        let control: AnyElement = match info.kind {
            Kind::Toggle => {
                let on = matches!(self.settings.get(key), Some(Setting::Bool(true)));
                let this = cx.entity().downgrade();
                Switch::new(key)
                    .checked(on)
                    .small()
                    .on_click(move |checked, window, cx| {
                        let _ = this.update(cx, |this, cx| {
                            this.set_setting(key, &Setting::Bool(*checked), window, cx);
                        });
                    })
                    .into_any_element()
            }
            Kind::Choice(names) => self.segmented(key, names, cx),
            Kind::Number { min, max, step } => self.number_box(key, (min, max, step), window, cx),
            Kind::Font { monospace } => self.font_picker(key, monospace, cx),
            Kind::Theme { .. } => self.theme_choice(key, cx),
            Kind::Program => self.program_field(key, window, cx),
            Kind::Relay => self.relay_choice(key, window, cx),
            Kind::Agent => self.agent_choice(cx),
        };
        div()
            .id(key)
            .flex()
            .items_center()
            .justify_between()
            .gap(self.z(16.0))
            .h(self.z(ROW))
            .px(self.z(8.0))
            .rounded(self.z(4.0))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .child(
                div()
                    .id(("name", key.len()))
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .child(info.name)
                    .tooltip(move |window, cx| Tooltip::new(tooltip).build(window, cx)),
            )
            .child(div().flex_none().child(control))
            .into_any_element()
    }

    /// Setting `key`'s field (made the first time) and whether it has the
    /// focus: Enter or leaving it sets the setting to what was typed
    /// (`set`, which says what the field then shows); when the setting
    /// becomes `now` other than by its typing, it shows `now` once it is
    /// not being typed in. Not on any frame where the two differ: leaving
    /// the field draws a frame before its blur is heard, which would put
    /// the setting back over the typing.
    fn setting_field(
        &mut self,
        key: &'static str,
        now: String,
        placeholder: &'static str,
        set: fn(&mut Self, &'static str, &str, &mut Window, &mut Context<Self>) -> String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> (Entity<InputState>, bool) {
        let (input, _, synced) = self.setting_inputs.entry(key).or_insert_with(|| {
            let input = cx.new(|cx| {
                InputState::new(window, cx)
                    .default_value(now.clone())
                    .placeholder(placeholder)
            });
            let changes = cx.subscribe_in(
                &input,
                window,
                move |this, input, e: &InputEvent, window, cx| {
                    if matches!(e, InputEvent::PressEnter { .. } | InputEvent::Blur) {
                        let text = input.read(cx).value().trim().to_owned();
                        let shows = set(this, key, &text, window, cx);
                        this.show_in_field(key, shows, window, cx);
                    }
                },
            );
            (input, changes, now.clone())
        });
        let input = input.clone();
        let focused = input.read(cx).focus_handle(cx).is_focused(window);
        if !focused && *synced != now {
            synced.clone_from(&now);
            input.update(cx, |s, cx| s.set_value(now, window, cx));
        }
        (input, focused)
    }

    /// Setting `key`'s field shows `text`, as the setting.
    fn show_in_field(
        &mut self,
        key: &'static str,
        text: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some((input, _, synced)) = self.setting_inputs.get_mut(key) {
            synced.clone_from(&text);
            input.update(cx, |s, cx| s.set_value(text, window, cx));
        }
    }

    /// A program (`python.interpreter`) as a field.
    fn program_field(
        &mut self,
        key: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let now = self.setting_value(key);
        let set = |this: &mut Self,
                   key: &'static str,
                   text: &str,
                   window: &mut Window,
                   cx: &mut Context<Self>| {
            if text != this.setting_value(key) {
                this.set_setting(key, &Setting::Text(text.to_owned()), window, cx);
            }
            this.setting_value(key)
        };
        let (input, focused) = self.setting_field(key, now, "", set, window, cx);
        self.text_field(&input, focused, 260.0)
    }

    /// A field of `width` (logical) holding `input`.
    fn text_field(&self, input: &Entity<InputState>, focused: bool, width: f32) -> AnyElement {
        let theme = self.theme;
        div()
            .w(self.z(width))
            .h(self.z(CONTROL))
            .px(self.z(4.0))
            .flex()
            .items_center()
            .border_1()
            .border_color(hsla(if focused {
                theme.border_focused
            } else {
                theme.border
            }))
            .rounded(self.z(4.0))
            .bg(hsla(solid(theme.editor)))
            .child(Input::new(input).appearance(false).small())
            .into_any_element()
    }

    /// The robot's agent (`agents.default`) as a button: its name, or
    /// Choose…; a click opens the agent picker.
    fn agent_choice(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let now = &self.settings.agent;
        let (label, color) = if now.is_empty() {
            ("Choose…".to_owned(), theme.text_muted)
        } else {
            (now.clone(), theme.text)
        };
        div()
            .id("agent")
            .pl(self.z(8.0))
            .pr(self.z(4.0))
            .h(self.z(CONTROL))
            .w(self.z(200.0))
            .flex()
            .items_center()
            .justify_between()
            .gap(self.z(4.0))
            .border_1()
            .border_color(hsla(theme.border))
            .rounded(self.z(4.0))
            .bg(hsla(solid(theme.editor)))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_click(cx.listener(|this, _, window, cx| {
                this.choose_agent(false, window, cx);
            }))
            .child(
                div()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .text_color(hsla(color))
                    .child(label),
            )
            .child(icon(
                IconName::ChevronDown,
                self.z(ICON - 2.0),
                hsla(theme.text_muted),
            ))
            .into_any_element()
    }

    /// The Agents group's own rows: each agent's command as a field (a
    /// built-in's own as its placeholder; changed, it is kept in
    /// `[agents.commands]`), "not found" beside a name whose program the
    /// user's shell doesn't find, × beside the user's own; then a row
    /// adding one.
    fn agent_setting_rows(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        let theme = self.theme;
        let mut rows = Vec::new();
        for (k, choice) in self.agent_choices(true, cx).into_iter().enumerate() {
            let name = choice.name.clone();
            let (now, placeholder, set): (String, String, FieldSet) = if choice.custom {
                let named = name.clone();
                let set: FieldSet = Rc::new(move |this, text, _, window, cx| {
                    let mut custom = this.settings.custom_agents.clone();
                    if let Some(agent) = custom.iter_mut().find(|a| a.name == named)
                        && !text.is_empty()
                        && agent.command != text
                    {
                        text.clone_into(&mut agent.command);
                        this.set_custom_agents(custom, window, cx);
                    }
                    this.settings
                        .custom_agents
                        .iter()
                        .find(|a| a.name == named)
                        .map(|a| a.command.clone())
                        .unwrap_or_default()
                });
                (choice.command.clone(), String::new(), set)
            } else {
                let named = name.clone();
                let set: FieldSet = Rc::new(move |this, text, _, window, cx| {
                    let changed = |this: &Workspace| {
                        this.settings
                            .agent_commands
                            .get(&named)
                            .cloned()
                            .unwrap_or_default()
                    };
                    if text != changed(this) {
                        this.set_agent_command(&named, text, window, cx);
                    }
                    changed(this)
                });
                let own = agents::harness(&name)
                    .and_then(|h| h.command)
                    .unwrap_or("no command known");
                let changed = self
                    .settings
                    .agent_commands
                    .get(&name)
                    .cloned()
                    .unwrap_or_default();
                (changed, own.to_owned(), set)
            };
            let (input, focused) =
                self.agent_field(format!("agent:{name}"), now, placeholder, set, window, cx);
            let field = self.text_field(&input, focused, AGENT_COMMAND);
            let left = div()
                .flex()
                .items_center()
                .gap(self.z(6.0))
                .child(name.clone())
                .when(choice.found == Some(false), |d| {
                    d.child(div().text_color(hsla(theme.text_muted)).child("not found"))
                })
                .into_any_element();
            let end = choice.custom.then(|| {
                div()
                    .id(("agent-remove", k))
                    .size(self.z(CONTROL))
                    .flex()
                    .items_center()
                    .justify_center()
                    .rounded(self.z(4.0))
                    .hover(|s| s.bg(hsla(theme.element_hover)))
                    .tooltip(|window, cx| Tooltip::new("Remove").build(window, cx))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        let custom = this
                            .settings
                            .custom_agents
                            .iter()
                            .filter(|a| a.name != name)
                            .cloned()
                            .collect();
                        this.set_custom_agents(custom, window, cx);
                        this.agent_inputs.remove(&format!("agent:{name}"));
                    }))
                    .child(icon(
                        IconName::X,
                        self.z(ICON - 2.0),
                        hsla(theme.text_muted),
                    ))
                    .into_any_element()
            });
            rows.push(self.agent_row(("agent-row", k), left, field, end));
        }
        rows.push(self.agent_add_row(window, cx));
        rows
    }

    /// The row adding an agent: its name and command as fields, and Add
    /// (Enter in the command field too; in the name field it moves to the
    /// command's while that is empty).
    fn agent_add_row(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let on_name: FieldSet = Rc::new(|this, _, enter, window, cx| {
            if enter {
                if this.agent_text(ADD_COMMAND, cx).is_empty() {
                    if let Some((input, ..)) = this.agent_inputs.get(ADD_COMMAND) {
                        let input = input.clone();
                        input.update(cx, |s, cx| s.focus(window, cx));
                    }
                } else {
                    this.add_agent(window, cx);
                }
            }
            this.agent_text(ADD_NAME, cx)
        });
        let on_command: FieldSet = Rc::new(|this, _, enter, window, cx| {
            if enter {
                this.add_agent(window, cx);
            }
            this.agent_text(ADD_COMMAND, cx)
        });
        // What is typed is what they show: never put back over it.
        let typed = (
            self.agent_text(ADD_NAME, cx),
            self.agent_text(ADD_COMMAND, cx),
        );
        let (name, name_focused) = self.agent_field(
            ADD_NAME.to_owned(),
            typed.0,
            "Name".to_owned(),
            on_name,
            window,
            cx,
        );
        let (command, command_focused) = self.agent_field(
            ADD_COMMAND.to_owned(),
            typed.1,
            "Command, as typed in a terminal".to_owned(),
            on_command,
            window,
            cx,
        );
        let left = self.text_field(&name, name_focused, AGENT_NAME);
        let field = self.text_field(&command, command_focused, AGENT_COMMAND);
        let add = div()
            .id("agent-add")
            .h(self.z(CONTROL))
            .px(self.z(6.0))
            .flex()
            .items_center()
            .rounded(self.z(4.0))
            .text_color(hsla(theme.text))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_click(cx.listener(|this, _, window, cx| this.add_agent(window, cx)))
            .child("Add")
            .into_any_element();
        self.agent_row("agent-add-row", left, field, Some(add))
    }

    /// An agent's row: `left` (its name), and right its command's `field`
    /// and `end` (×, Add) in a slot of their own.
    fn agent_row(
        &self,
        id: impl Into<ElementId>,
        left: AnyElement,
        field: AnyElement,
        end: Option<AnyElement>,
    ) -> AnyElement {
        let theme = self.theme;
        div()
            .id(id)
            .flex()
            .items_center()
            .justify_between()
            .gap(self.z(16.0))
            .h(self.z(ROW))
            .px(self.z(8.0))
            .rounded(self.z(4.0))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .child(
                div()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .child(left),
            )
            .child(
                div()
                    .flex_none()
                    .flex()
                    .items_center()
                    .gap(self.z(4.0))
                    .child(field)
                    .child(
                        div()
                            .w(self.z(AGENT_END))
                            .flex()
                            .justify_center()
                            .children(end),
                    ),
            )
            .into_any_element()
    }

    /// An agent's field `key` (made the first time) and whether it has the
    /// focus, as [`Self::setting_field`]: Enter or leaving it hands the
    /// text typed to `set`, which says what it then shows.
    fn agent_field(
        &mut self,
        key: String,
        now: String,
        placeholder: String,
        set: FieldSet,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> (Entity<InputState>, bool) {
        let (input, _, synced) = self.agent_inputs.entry(key.clone()).or_insert_with(|| {
            let input = cx.new(|cx| {
                InputState::new(window, cx)
                    .default_value(now.clone())
                    .placeholder(placeholder)
            });
            let changes = cx.subscribe_in(
                &input,
                window,
                move |this, input, e: &InputEvent, window, cx| {
                    let enter = matches!(e, InputEvent::PressEnter { .. });
                    if enter || matches!(e, InputEvent::Blur) {
                        let text = input.read(cx).value().trim().to_owned();
                        let shows = set(this, &text, enter, window, cx);
                        this.show_in_agent_field(&key, shows, window, cx);
                    }
                },
            );
            (input, changes, now.clone())
        });
        let input = input.clone();
        let focused = input.read(cx).focus_handle(cx).is_focused(window);
        if !focused && *synced != now {
            synced.clone_from(&now);
            input.update(cx, |s, cx| s.set_value(now, window, cx));
        }
        (input, focused)
    }

    /// Agent field `key` shows `text`.
    fn show_in_agent_field(
        &mut self,
        key: &str,
        text: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some((input, _, synced)) = self.agent_inputs.get_mut(key) {
            synced.clone_from(&text);
            input.update(cx, |s, cx| s.set_value(text, window, cx));
        }
    }

    /// What agent field `key` holds, trimmed.
    fn agent_text(&self, key: &str, cx: &Context<Self>) -> String {
        self.agent_inputs
            .get(key)
            .map(|(input, ..)| input.read(cx).value().trim().to_owned())
            .unwrap_or_default()
    }

    /// Add: the agent typed in the adding row made one of the user's own,
    /// its fields emptied; a name taken or a field empty is said instead.
    fn add_agent(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let name = self.agent_text(ADD_NAME, cx);
        let command = self.agent_text(ADD_COMMAND, cx);
        let taken = agents::launchables(&self.settings)
            .iter()
            .any(|a| a.name.eq_ignore_ascii_case(&name));
        let problem = if name.is_empty() {
            Some("An agent needs a name.".to_owned())
        } else if taken {
            Some(format!("There is an agent named {name} already."))
        } else if command.is_empty() {
            Some(format!("{name} needs a command to start it."))
        } else {
            None
        };
        if let Some(problem) = problem {
            self.error = Some(problem);
            cx.notify();
            return;
        }
        let mut custom = self.settings.custom_agents.clone();
        custom.push(CustomAgent { name, command });
        self.set_custom_agents(custom, window, cx);
        self.show_in_agent_field(ADD_NAME, String::new(), window, cx);
        self.show_in_agent_field(ADD_COMMAND, String::new(), window, cx);
    }

    /// The relay (`collab.relay`): binbun, n0 or Custom as segments, and
    /// for Custom the relay's URL as a field.
    fn relay_choice(
        &mut self,
        key: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let url = match &self.settings.collab_relay {
            CollabRelay::Custom(url) => Some(url.clone()),
            CollabRelay::Binbun | CollabRelay::N0 => None,
        };
        let custom = self.relay_custom || url.is_some();
        let now = self.settings.collab_relay.name().to_owned();
        let chosen = move |name: &str| {
            if custom {
                name == "Custom"
            } else {
                name == now
            }
        };
        let click =
            move |this: &mut Self, name: &str, window: &mut Window, cx: &mut Context<Self>| {
                if name == "Custom" {
                    this.relay_custom = true;
                    cx.notify();
                } else {
                    this.relay_custom = false;
                    this.set_setting(key, &Setting::Text(name.to_owned()), window, cx);
                }
            };
        let segments = self.segments(RELAYS, chosen, click, cx);
        let field = custom.then(|| {
            let set = |this: &mut Self,
                       key: &'static str,
                       text: &str,
                       window: &mut Window,
                       cx: &mut Context<Self>| {
                // Only while Custom is chosen: leaving the field for binbun
                // or n0 does not set the URL typed.
                let custom = this.relay_custom
                    || matches!(this.settings.collab_relay, CollabRelay::Custom(_));
                if !custom || text.is_empty() {
                    return text.to_owned();
                }
                let typed = Setting::Text(text.to_owned());
                if this.settings.get(key).as_ref() == Some(&typed) {
                    // Already the setting: the error of a URL refused here
                    // before goes, not one from elsewhere.
                    if let Some(refused) = this.relay_refused.take()
                        && this.settings_error.as_ref() == Some(&refused)
                    {
                        this.settings_error = None;
                        cx.notify();
                    }
                } else {
                    this.set_setting(key, &typed, window, cx);
                    this.relay_refused = if this.settings.get(key) == Some(typed) {
                        None
                    } else {
                        this.settings_error.clone()
                    };
                }
                // What was typed, a URL refused too: the error says why.
                text.to_owned()
            };
            let (input, focused) = self.setting_field(
                key,
                url.unwrap_or_default(),
                "https://relay.example.org",
                set,
                window,
                cx,
            );
            self.text_field(&input, focused, RELAY_URL)
        });
        div()
            .flex()
            .items_center()
            .gap(self.z(6.0))
            .child(segments)
            .children(field)
            .into_any_element()
    }

    /// A choice as compact segments.
    fn segmented(
        &self,
        key: &'static str,
        names: &'static [&'static str],
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let now = self.setting_value(key);
        self.segments(
            names,
            move |name| name == now,
            move |this, name, window, cx| {
                this.set_setting(key, &Setting::Text(name.to_owned()), window, cx);
            },
            cx,
        )
    }

    /// `names` as compact segments, those `chosen` says highlighted; a
    /// click on one runs `click` with its name.
    fn segments(
        &self,
        names: &'static [&'static str],
        chosen: impl Fn(&str) -> bool,
        click: impl Fn(&mut Self, &str, &mut Window, &mut Context<Self>) + Clone + 'static,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        div()
            .flex()
            .h(self.z(CONTROL))
            .border_1()
            .border_color(hsla(theme.border))
            .rounded(self.z(4.0))
            .overflow_hidden()
            .children(names.iter().map(|&name| {
                let on = chosen(name);
                let click = click.clone();
                div()
                    .id(name)
                    .px(self.z(8.0))
                    .h_full()
                    .flex()
                    .items_center()
                    .when(on, |d| d.bg(hsla(theme.element_selected)))
                    .text_color(hsla(if on { theme.text } else { theme.text_muted }))
                    .hover(|s| s.bg(hsla(theme.element_hover)))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        click(this, name, window, cx);
                    }))
                    .child(name)
            }))
            .into_any_element()
    }

    /// A number as a small box: typed in (a number off its steps goes to
    /// the nearest; one out of its bounds to the bound), stepped by Up and
    /// Down while it has the focus and by the wheel over it.
    fn number_box(
        &mut self,
        key: &'static str,
        (min, max, step): (f64, f64, f64),
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let value = match self.settings.get(key) {
            Some(Setting::Number(n)) => n,
            _ => min,
        };
        let set = |this: &mut Self,
                   key: &'static str,
                   text: &str,
                   window: &mut Window,
                   cx: &mut Context<Self>| {
            let Some(&Info {
                kind: Kind::Number { min, max, step },
                ..
            }) = SETTINGS.iter().find(|i| i.key == key)
            else {
                return text.to_owned();
            };
            let to = match text.parse::<f64>() {
                Ok(typed) if typed.is_finite() => on_step(typed, step).clamp(min, max),
                // Not a number: the box shows the setting again.
                Ok(_) | Err(_) => match this.settings.get(key) {
                    Some(Setting::Number(n)) => n,
                    _ => min,
                },
            };
            if this.settings.get(key) != Some(Setting::Number(to)) {
                this.set_setting(key, &Setting::Number(to), window, cx);
            }
            // What was typed, as set (`13.0` as `13`, `99` as the bound).
            shown(to)
        };
        let (input, focused) = self.setting_field(key, shown(value), "", set, window, cx);
        let to = move |by: f64| on_step(value + by * step, step).clamp(min, max);
        let step_to =
            move |this: &mut Self, to: f64, window: &mut Window, cx: &mut Context<Self>| {
                this.set_setting(key, &Setting::Number(to), window, cx);
                this.show_in_field(key, shown(to), window, cx);
            };
        div()
            .id("number")
            .w(self.z(NUMBER))
            .h(self.z(CONTROL))
            .px(self.z(4.0))
            .flex()
            .items_center()
            .border_1()
            .border_color(hsla(if focused {
                theme.border_focused
            } else {
                theme.border
            }))
            .rounded(self.z(4.0))
            .bg(hsla(solid(theme.editor)))
            .font_features(tabular())
            .on_scroll(cx.listener(move |this, e: &ScrollEvent, window, cx| {
                let up = match wheel(e) {
                    binbun_gui_view::scroll::Wheel::Lines(y)
                    | binbun_gui_view::scroll::Wheel::Pixels(y) => y,
                };
                if up != 0.0 {
                    step_to(this, to(up.signum().into()), window, cx);
                }
                cx.stop_propagation();
            }))
            .capture_key_down(cx.listener(move |this, e: &KeyDownEvent, window, cx| {
                let by = match e.keystroke.key.as_str() {
                    "up" => 1.0,
                    "down" => -1.0,
                    "pageup" => 10.0,
                    "pagedown" => -10.0,
                    _ => return,
                };
                step_to(this, to(by), window, cx);
                cx.stop_propagation();
            }))
            .child(Input::new(&input).appearance(false).small().text_right())
            .into_any_element()
    }

    /// A font setting's dropdown and, when open, its list.
    fn font_picker(
        &self,
        key: &'static str,
        monospace: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let now = self.setting_value(key);
        let open = self
            .font_menu
            .as_ref()
            .filter(|(k, _, _)| *k == key)
            .map(|(_, p, _)| p.clone());
        div()
            .id("font")
            .relative()
            .pl(self.z(8.0))
            .pr(self.z(4.0))
            .h(self.z(CONTROL))
            .w(self.z(200.0))
            .flex()
            .items_center()
            .justify_between()
            .gap(self.z(4.0))
            .border_1()
            .border_color(hsla(theme.border))
            .rounded(self.z(4.0))
            .bg(hsla(solid(theme.editor)))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, window, cx| {
                    // Pressed again, its open menu closes.
                    window.prevent_default();
                    cx.stop_propagation();
                    if this
                        .font_menu
                        .as_ref()
                        .is_some_and(|(open, ..)| *open == key)
                    {
                        this.font_menu = None;
                        cx.notify();
                    } else {
                        this.open_font_menu(key, monospace, window, cx);
                    }
                }),
            )
            .child(
                div()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .font(font(now.clone()))
                    .child(now),
            )
            .child(icon(
                IconName::ChevronDown,
                self.z(ICON - 2.0),
                hsla(theme.text_muted),
            ))
            .when_some(open, |d, popup| {
                d.child(deferred(
                    anchored()
                        .snap_to_window_with_margin(px(popup::MARGIN))
                        .child(div().occlude().mt(self.z(CONTROL + 2.0)).child(popup)),
                ))
            })
            .into_any_element()
    }

    /// A theme setting's button: the theme's name; a click opens Select
    /// Theme.
    fn theme_choice(&self, key: &'static str, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let now = self.setting_value(key);
        div()
            .id("theme")
            .pl(self.z(8.0))
            .pr(self.z(4.0))
            .h(self.z(CONTROL))
            .w(self.z(200.0))
            .flex()
            .items_center()
            .justify_between()
            .gap(self.z(4.0))
            .border_1()
            .border_color(hsla(theme.border))
            .rounded(self.z(4.0))
            .bg(hsla(solid(theme.editor)))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_click(cx.listener(|this, _, window, cx| {
                this.open_picker(PickerKind::Theme, window, cx);
            }))
            .child(
                div()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .child(now),
            )
            .child(icon(
                IconName::ChevronDown,
                self.z(ICON - 2.0),
                hsla(theme.text_muted),
            ))
            .into_any_element()
    }

    fn open_font_menu(
        &mut self,
        key: &'static str,
        monospace: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let families = if monospace {
            let mut all: Vec<String> = BUNDLED_CODE.iter().map(|&s| s.to_owned()).collect();
            for name in self.monospace_fonts(window) {
                if !all.contains(&name) {
                    all.push(name);
                }
            }
            all
        } else {
            let mut all: Vec<String> = BUNDLED_UI.iter().map(|&s| s.to_owned()).collect();
            let mut installed = window.text_system().all_font_names();
            installed.sort();
            installed.dedup();
            all.extend(
                installed
                    .into_iter()
                    .filter(|n| !n.starts_with('.') && !BUNDLED_UI.contains(&n.as_str())),
            );
            all
        };
        let now = self.setting_value(key);
        let this = cx.entity().downgrade();
        let popup = PopupMenu::build(window, cx, move |mut m, window, _| {
            for family in &families {
                let shown = family.clone();
                let chosen = family.clone();
                let this = this.clone();
                m = m.item(
                    PopupMenuItem::element(move |_, _| {
                        div().font(font(shown.clone())).child(shown.clone())
                    })
                    .checked(*family == now)
                    .on_click(move |_, window, cx| {
                        let _ = this.update(cx, |this, cx| {
                            this.font_menu = None;
                            this.set_setting(key, &Setting::Text(chosen.clone()), window, cx);
                        });
                    }),
                );
            }
            // A list's height at most, and no more than the window has.
            let room = popup::room(window, px(popup::MARGIN));
            m.max_h(px(420.0).min(room))
                .scrollable(true)
                .min_w(px(260.0))
        });
        let sub = cx.subscribe_in(&popup, window, |this, _, _: &DismissEvent, _, cx| {
            this.font_menu = None;
            cx.notify();
        });
        popup.update(cx, |p, cx| {
            let handle = p.focus_handle(cx);
            window.focus(&handle, cx);
        });
        self.font_menu = Some((key, popup, sub));
        cx.notify();
    }

    /// The installed families whose `i` is as wide as their `M`, found once.
    fn monospace_fonts(&mut self, window: &Window) -> Vec<String> {
        if let Some(found) = &self.mono_fonts {
            return found.clone();
        }
        let ts = window.text_system();
        let mut names = ts.all_font_names();
        names.sort();
        names.dedup();
        let found: Vec<String> = names
            .into_iter()
            .filter(|name| !name.starts_with('.'))
            .filter(|name| {
                let id = ts.resolve_font(&font(name.clone()));
                let width = |c| ts.advance(id, px(16.0), c).map(|s| f32::from(s.width)).ok();
                matches!((width('i'), width('M')), (Some(i), Some(m)) if i > 0.0 && (i - m).abs() < 0.01)
            })
            .collect();
        self.mono_fonts = Some(found.clone());
        found
    }
}
