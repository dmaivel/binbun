//! The coding agents the robot in the status bar starts
//! ([`agents::launchables`]): a click starts the default (the one started
//! last; asked the first time), each in a terminal of a new pane right of
//! the focused one. Its right-click menu lists the agents running here, a
//! new one of each, Change Agent…, Hide Agents Not Found and Customize…
//! (Settings › Agents, where the commands are changed and the user's own
//! agents added).

use binbun_gui_view::agents;
use binbun_gui_view::settings::{CustomAgent, Setting, Settings};
use gpui_kit::assets::IconName;
use gpui_kit::{Context, Pixels, Point, SharedString, Window};

use crate::context_menu::OwnItem;
use crate::icons::mark_icon;
use crate::settings_pane::AGENTS;
use crate::workspace::{PickerKind, TabKind, Workspace};

/// An agent offered (by the picker, the menu, the settings), as it was
/// when they opened.
pub struct AgentChoice {
    /// Its name.
    pub name: String,
    /// What starts it; empty if none is known.
    pub command: String,
    /// Whether its program is found on the user's `PATH`: `None` while
    /// that is read; `Some(false)` without a command.
    pub found: Option<bool>,
    /// One of the user's own (`[[agents.custom]]`).
    pub custom: bool,
    /// Its icon's asset path: its harness's mark, else the robot.
    pub icon: SharedString,
}

impl AgentChoice {
    /// Whether it has a command to start it by.
    pub fn runnable(&self) -> bool {
        agents::command_program(&self.command).is_some()
    }
}

/// Agent `name`'s icon's asset path: its harness's single-colour mark
/// framed as an icon, else the robot (Gemini CLI, the user's own).
pub fn agent_icon(name: &str) -> SharedString {
    agents::HARNESSES
        .iter()
        .find(|h| h.name == name)
        .and_then(|h| h.mark)
        .map_or_else(|| IconName::Bot.path(), |mark| mark_icon(&mark))
}

impl Workspace {
    /// Every agent the robot can start, with whether its program is found;
    /// those not found are left out when Hide Agents Not Found is on,
    /// unless `all`.
    pub fn agent_choices(&mut self, all: bool, cx: &mut Context<Self>) -> Vec<AgentChoice> {
        let path = self.login_path(cx);
        let hide = self.settings.hide_missing_agents && !all;
        agents::launchables(&self.settings)
            .into_iter()
            .map(|agent| {
                let found = match agents::command_program(&agent.command) {
                    None => Some(false),
                    Some(program) => path.as_ref().map(|path| agents::found(program, Some(path))),
                };
                AgentChoice {
                    custom: agent.harness.is_none(),
                    icon: agent_icon(&agent.name),
                    name: agent.name,
                    command: agent.command,
                    found,
                }
            })
            .filter(|choice| !(hide && choice.found == Some(false)))
            .collect()
    }

    /// New Agent (the robot's click): the default agent started; with none
    /// (or one gone from the settings), the picker asks which, then starts
    /// it.
    pub fn new_agent(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let default = self.settings.agent.clone();
        let agent = agents::launchables(&self.settings).into_iter().find(|a| {
            !default.is_empty()
                && a.name == default
                && agents::command_program(&a.command).is_some()
        });
        match agent {
            Some(agent) => self.start_agent(&agent.name, &agent.command, window, cx),
            None => self.choose_agent(true, window, cx),
        }
    }

    /// The agent picker: `launch`, it starts the agent chosen; else it only
    /// makes it the robot's.
    pub fn choose_agent(&mut self, launch: bool, window: &mut Window, cx: &mut Context<Self>) {
        self.terminals.pick_launches = launch;
        self.agent_choices = self.agent_choices(false, cx);
        self.open_picker(PickerKind::Agent, window, cx);
    }

    /// Agent `name` started by `command`, and made the robot's.
    fn start_agent(
        &mut self,
        name: &str,
        command: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.settings.agent != name {
            self.set_setting(
                "agents.default",
                &Setting::Text(name.to_owned()),
                window,
                cx,
            );
        }
        self.open_agent_terminal(name, command, window, cx);
    }

    /// Enter in the agent picker: the agent selected made the robot's, and
    /// started if the picker was opened to start one.
    pub fn confirm_agent(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(choice) = self
            .picker
            .as_ref()
            .and_then(|p| p.rows.get(p.selected))
            .and_then(|(i, _)| self.agent_choices.get(*i))
        else {
            return;
        };
        let (name, command, runnable) = (
            choice.name.clone(),
            choice.command.clone(),
            choice.runnable(),
        );
        self.picker = None;
        let launch = std::mem::take(&mut self.terminals.pick_launches);
        let id = self.layout.focused();
        self.focus_pane(id, window, cx);
        match (launch, runnable) {
            (true, true) => self.start_agent(&name, &command, window, cx),
            (true, false) => {
                self.set_setting("agents.default", &Setting::Text(name.clone()), window, cx);
                self.error = Some(format!(
                    "{name} has no command to start it: set one in Settings › Agents."
                ));
            }
            (false, _) => self.set_setting("agents.default", &Setting::Text(name), window, cx),
        }
    }

    /// The robot's right-click menu: the agents it started that run here
    /// (shown when picked), a new one of each agent (greyed when its
    /// program is not found), Change Agent…, Hide Agents Not Found and
    /// Customize….
    pub fn agent_menu(&mut self, at: Point<Pixels>, window: &mut Window, cx: &mut Context<Self>) {
        let shown =
            |this: &Self, kind: &TabKind| this.place_of(kind).is_some_and(|(_, _, shown)| shown);
        let mut items = Vec::new();
        for (id, name) in self.launched_agents() {
            items.push(OwnItem {
                checked: shown(self, &TabKind::Terminal(id)),
                icon: Some(agent_icon(&name)),
                ..OwnItem::new(self.terminal_title(id), move |this, window, cx| {
                    this.show_shell(TabKind::Terminal(id), false, window, cx);
                })
            });
        }
        for choice in self.agent_choices(false, cx) {
            let label = match (choice.runnable(), choice.found) {
                (false, _) => format!("New {} (no command)", choice.name),
                (true, Some(false)) => format!("New {} (not found)", choice.name),
                (true, Some(true) | None) => format!("New {}", choice.name),
            };
            let enabled = choice.runnable() && choice.found != Some(false);
            let checked = choice.name == self.settings.agent;
            let AgentChoice {
                name,
                command,
                icon,
                ..
            } = choice;
            items.push(OwnItem {
                enabled,
                checked,
                icon: Some(icon),
                ..OwnItem::new(label, move |this, window, cx| {
                    this.start_agent(&name, &command, window, cx);
                })
            });
        }
        items.push(OwnItem::new("Change Agent…", |this, window, cx| {
            this.choose_agent(false, window, cx);
        }));
        items.push(OwnItem {
            checked: self.settings.hide_missing_agents,
            ..OwnItem::new("Hide Agents Not Found", |this, window, cx| {
                let hide = !this.settings.hide_missing_agents;
                this.set_setting("agents.hide_missing", &Setting::Bool(hide), window, cx);
            })
        });
        items.push(OwnItem::new("Customize…", Self::customize_agents));
        self.toggle_own_menu("agent-launch", at, items, window, cx);
    }

    /// Customize…: the settings opened at their Agents group (the search
    /// cleared, so it shows).
    pub fn customize_agents(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(search) = self.settings_search.clone() {
            search.update(cx, |s, cx| s.set_value("", window, cx));
        }
        let id = self.layout.focused();
        self.open_tab(id, TabKind::Settings, window, cx);
        self.settings_jump = Some((AGENTS, false));
        cx.notify();
    }

    /// The built-in agent `name`'s command set to `command` (its own again
    /// when empty or the same), and saved.
    pub fn set_agent_command(
        &mut self,
        name: &str,
        command: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let own = agents::harness(name)
            .and_then(|h| h.command)
            .unwrap_or_default();
        let command = if command == own { "" } else { command };
        let mut next = self.settings.clone();
        if command.is_empty() {
            next.agent_commands.remove(name);
        } else {
            next.agent_commands
                .insert(name.to_owned(), command.to_owned());
        }
        self.settings_file.set_agent_command(name, command);
        self.save_settings_file();
        self.apply_settings(next, window, cx);
    }

    /// The user's own agents made `custom`, and saved.
    pub fn set_custom_agents(
        &mut self,
        custom: Vec<CustomAgent>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.settings_file.set_custom_agents(&custom);
        let next = Settings {
            custom_agents: custom,
            ..self.settings.clone()
        };
        self.save_settings_file();
        self.apply_settings(next, window, cx);
    }
}
