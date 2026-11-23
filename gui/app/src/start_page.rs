//! The start page, in the editor area while no binary is open: the logo,
//! its actions (Open file…; Join… in a binbun with collaboration), and
//! the files opened before (pinned first, then the newest), each a row
//! with its name (a share's project's, "bash, shared by Ann": each project
//! of a file is its own row, opened in that project), its folder dimmed,
//! its format and architecture from its
//! header, when it was last opened, and a mark if its project holds
//! edits; a file opened once but missing now (moved, on a drive not
//! mounted) is dimmed, and what never opened is not listed.
//! Keyboard first (arrows, Enter; Ctrl+R gives it the focus); a right
//! click pins or removes. Nothing else: no tips, no
//! news. A file dropped anywhere on the window opens it (the drop target
//! shows only while a file is dragged over the window).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use binbun_gui_view::commands::{Command, key_label};
use binbun_gui_view::projects::project_title;
use binbun_gui_view::recent::{self, Recent};
use binbun_gui_view::session::project;
use binbun_gui_view::settings::Dropped;
use gpui_kit::assets::IconName;
use gpui_kit::component::menu::{ContextMenuExt as _, PopupMenuItem};
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, Div, ExternalPaths, KeyDownEvent, Stateful, Window, WindowBounds,
    WindowOptions, div, px, size, svg,
};

use crate::actions::register_window;
use crate::icons::{LOGO, icon};
use crate::scrolling::Area;
use crate::sidebar::tabular;
use crate::theme::{hsla, with_alpha};
use crate::workspace::{ICON, Workspace, f};

/// The page's column (logical).
const COLUMN: f32 = 640.0;
/// The logo's size (logical).
const LOGO_SIZE: f32 = 48.0;
/// A recent file's row (logical): the tree's 22 and a little.
const ROW: f32 = 26.0;

/// What the start page shows of a recent file beside its path, read once.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StartFacts {
    /// Its title: its name, or a share's project's ("bash, shared by
    /// Ann").
    pub title: String,
    /// Its format and architecture (`x86-64 ELF`), if its header says.
    pub platform: Option<String>,
    /// Whether it is still there.
    pub exists: bool,
    /// Whether its project holds edits.
    pub edits: bool,
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Workspace {
    /// Replaces the recent files with `list` and saves them.
    pub fn set_recent(&mut self, list: Vec<Recent>) {
        self.recent = list;
        self.start_selected = self.start_selected.min(self.recent.len().saturating_sub(1));
        if let Some(file) = recent::path()
            && let Err(error) = recent::save(&file, &self.recent)
        {
            self.error = Some(error);
        }
    }

    /// Pins the recent entry of `path` in `project`, or unpins it.
    fn pin_recent(&mut self, path: &Path, project: Option<&str>) {
        self.set_recent(recent::toggle_pin(&self.recent, path, project));
    }

    /// Removes the recent entry of `path` in `project`.
    fn remove_recent(&mut self, path: &Path, project: Option<&str>) {
        self.set_recent(recent::remove(&self.recent, path, project));
    }

    /// The facts of recent file `recent`, read the first time.
    fn start_facts_of(&mut self, recent: &Recent) -> StartFacts {
        let path = &recent.path;
        let root = project::root();
        self.start_facts
            .entry((path.clone(), recent.project.clone()))
            .or_insert_with(|| {
                let name = path.file_name().map_or_else(
                    || path.display().to_string(),
                    |n| n.to_string_lossy().into_owned(),
                );
                let dir = root
                    .as_ref()
                    .zip(recent.project.as_ref())
                    .map(|(root, project)| root.join(project));
                StartFacts {
                    title: project_title(&name, dir.as_deref()),
                    platform: recent::platform_of(path),
                    exists: path.exists(),
                    edits: root.is_some_and(|root| recent::has_project(recent, &root)),
                }
            })
            .clone()
    }

    /// Opens recent file `k`, in the project it was opened in if that is
    /// still there.
    fn open_recent_at(&mut self, k: usize, window: &mut Window, cx: &mut Context<Self>) {
        let Some(recent) = self.recent.get(k).cloned() else {
            return;
        };
        if recent.path.exists() {
            self.open_recent(&recent, window, cx);
        }
    }

    /// Opens `recent` in the project it was opened in if that is still
    /// there, else as any file is opened.
    pub fn open_recent(&mut self, recent: &Recent, window: &mut Window, cx: &mut Context<Self>) {
        let dir = project::root()
            .zip(recent.project.as_ref())
            .map(|(root, project)| root.join(project))
            .filter(|dir| dir.is_dir());
        self.open_in_focused(recent.path.clone(), dir, window, cx);
    }

    fn start_keys(&mut self, e: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        if e.keystroke.modifiers.modified() {
            return;
        }
        let n = self.recent.len();
        let k = self.start_selected;
        match e.keystroke.key.as_str() {
            "up" => self.start_selected = k.saturating_sub(1),
            "down" => self.start_selected = (k + 1).min(n.saturating_sub(1)),
            "home" => self.start_selected = 0,
            "end" => self.start_selected = n.saturating_sub(1),
            "enter" => {
                self.open_recent_at(k, window, cx);
                cx.stop_propagation();
                return;
            }
            "delete" => {
                if let Some(r) = self.recent.get(k).cloned() {
                    self.remove_recent(&r.path, r.project.as_deref());
                }
            }
            _ => return,
        }
        let top = f(self.start_selected as u64) * ROW;
        let (top, height) = (f32::from(self.z(top)), f32::from(self.z(ROW)));
        self.reveal_in_area(Area::Start, top, height);
        cx.stop_propagation();
        cx.notify();
    }

    /// The start page.
    pub fn render_start(&mut self, window: &Window, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let focused = self.start_focus.is_focused(window);
        let now = unix_now();
        let open = self.start_action(
            "start-open",
            IconName::FolderOpen,
            "Open file…",
            Command::Open,
            cx,
        );
        // Join a shared session, in a binbun with collaboration.
        let join = cfg!(feature = "collab").then(|| {
            self.start_action(
                "start-join",
                IconName::Users,
                "Join…",
                Command::JoinSession,
                cx,
            )
        });
        let entries: Vec<(usize, Recent, StartFacts)> = (0..self.recent.len())
            .filter_map(|k| {
                let r = self.recent.get(k)?.clone();
                let facts = self.start_facts_of(&r);
                Some((k, r, facts))
            })
            .collect();
        let rows: Vec<AnyElement> = entries
            .into_iter()
            .map(|(k, r, facts)| self.start_row(k, &r, &facts, now, focused, cx))
            .collect();
        let list = div().flex().flex_col().children(rows);
        let list = self
            .scroll_area(Area::Start, "start-recent", list, cx)
            .flex_1()
            .min_h_0();
        div()
            .id("start")
            .key_context("Start")
            .track_focus(&self.start_focus)
            .size_full()
            .flex()
            .justify_center()
            .bg(hsla(theme.editor))
            .rounded(self.island_corner())
            .capture_key_down(cx.listener(|this, e: &KeyDownEvent, window, cx| {
                this.start_keys(e, window, cx);
            }))
            .child(
                div()
                    .w_full()
                    .max_w(self.z(COLUMN))
                    .h_full()
                    .px(self.z(12.0))
                    .pt(self.z(72.0))
                    .pb(self.z(24.0))
                    .flex()
                    .flex_col()
                    .gap(self.z(4.0))
                    .child(
                        svg()
                            .path(LOGO)
                            .size(self.z(LOGO_SIZE))
                            .flex_none()
                            .ml(self.z(8.0))
                            .mb(self.z(20.0))
                            .text_color(hsla(theme.text_muted)),
                    )
                    .child(open)
                    .children(join)
                    .child(
                        div()
                            .h(px(1.0))
                            .my(self.z(6.0))
                            .bg(hsla(theme.border_variant)),
                    )
                    .child(list),
            )
            .into_any_element()
    }

    /// An action's row above the recent files: its icon, `label`, and its
    /// key on the right; a click runs `command`.
    fn start_action(
        &self,
        id: &'static str,
        glyph: IconName,
        label: &'static str,
        command: Command,
        cx: &mut Context<Self>,
    ) -> Stateful<Div> {
        let theme = self.theme;
        div()
            .id(id)
            .h(self.z(ROW))
            .px(self.z(8.0))
            .flex()
            .items_center()
            .gap(self.z(8.0))
            .rounded(self.z(4.0))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_click(cx.listener(move |this, _, window, cx| this.run(command, window, cx)))
            .child(icon(glyph, self.z(ICON), hsla(theme.text_muted)))
            .child(div().flex_1().child(label))
            .when_some(key_label(&self.keymap, command), |d, key| {
                d.child(div().text_color(hsla(theme.text_placeholder)).child(key))
            })
    }

    /// A recent file's format and architecture (`x86-64 ELF`), on one
    /// line in a column wide enough for the longest (`AArch64 Mach-O`).
    fn platform_cell(&self, platform: Option<String>, color: u32) -> Div {
        div()
            .flex_none()
            .w(self.z(120.0))
            .overflow_hidden()
            .whitespace_nowrap()
            .text_ellipsis()
            .text_color(hsla(color))
            .child(platform.unwrap_or_default())
    }

    /// Recent file `k`'s row.
    fn start_row(
        &self,
        k: usize,
        r: &Recent,
        facts: &StartFacts,
        now: u64,
        focused: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let selected = k == self.start_selected;
        let name = facts.title.clone();
        let folder = r
            .path
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let (text, muted) = if facts.exists {
            (theme.text, theme.text_muted)
        } else {
            (theme.text_placeholder, theme.text_placeholder)
        };
        let path = r.path.clone();
        let project = r.project.clone();
        let pinned = r.pinned;
        let this = cx.entity().downgrade();
        div()
            .id(("recent", k))
            .h(self.z(ROW))
            .px(self.z(8.0))
            .flex()
            .items_center()
            .gap(self.z(10.0))
            .rounded(self.z(4.0))
            .when(selected && focused, |d| d.bg(hsla(theme.element_selected)))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_click(cx.listener(move |this, _, window, cx| {
                this.start_selected = k;
                window.focus(&this.start_focus, cx);
                this.open_recent_at(k, window, cx);
                cx.notify();
            }))
            .child(div().w(self.z(14.0)).flex_none().when(pinned, |d| {
                d.child(icon(IconName::Pin, self.z(12.0), hsla(muted)))
            }))
            .child(
                div()
                    .flex_none()
                    .max_w(self.z(220.0))
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .text_color(hsla(text))
                    .child(name),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .text_color(hsla(theme.text_placeholder))
                    .child(folder),
            )
            .child(div().flex_none().w(self.z(14.0)).when(facts.edits, |d| {
                d.child(icon(IconName::Pencil, self.z(12.0), hsla(muted)))
            }))
            .child(self.platform_cell(facts.platform.clone(), muted))
            .child(
                div()
                    .flex_none()
                    .w(self.z(44.0))
                    .flex()
                    .justify_end()
                    .text_color(hsla(muted))
                    .font_features(tabular())
                    .child(recent::ago(r.opened, now)),
            )
            .context_menu(move |menu, _, _| {
                let (pin_path, remove_path) = (path.clone(), path.clone());
                let (pin_project, remove_project) = (project.clone(), project.clone());
                let (pin_this, remove_this) = (this.clone(), this.clone());
                menu.item(
                    PopupMenuItem::new(if pinned { "Unpin" } else { "Pin" }).on_click(
                        move |_, _, cx| {
                            let _ = pin_this.update(cx, |this, cx| {
                                this.pin_recent(&pin_path, pin_project.as_deref());
                                cx.notify();
                            });
                        },
                    ),
                )
                .item(PopupMenuItem::new("Remove").on_click(move |_, _, cx| {
                    let _ = remove_this.update(cx, |this, cx| {
                        this.remove_recent(&remove_path, remove_project.as_deref());
                        cx.notify();
                    });
                }))
            })
            .into_any_element()
    }

    /// Files dropped on the window: the first opens, here (with no binary
    /// open, or as the setting says) or in a new window.
    pub fn open_dropped(
        &mut self,
        paths: &ExternalPaths,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(path) = paths.paths().first().cloned() else {
            return;
        };
        if self.session.is_some() && self.settings.drop == Dropped::NewWindow {
            if !open_window(Some(&path), cx) {
                self.error = Some("cannot open a window".to_owned());
            }
            return;
        }
        self.open_focused(path, window, cx);
    }

    /// The drop target over the editor area: drawn only while a file is
    /// dragged over the window (a dashed accent outline and `Open`).
    pub fn drop_target(&self) -> AnyElement {
        let theme = self.theme;
        let gap = self.z(6.0);
        div()
            .absolute()
            .inset_0()
            .opacity(0.0)
            .drag_over::<ExternalPaths>(move |style, _, _, _| style.opacity(1.0))
            .child(
                div()
                    .absolute()
                    .top(gap)
                    .bottom(gap)
                    .left(gap)
                    .right(gap)
                    .border_2()
                    .border_dashed()
                    .border_color(hsla(theme.accent))
                    .rounded(self.z(8.0))
                    .bg(hsla(with_alpha(theme.editor, 0xcc)))
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_color(hsla(theme.accent))
                    .text_size(self.z(self.settings.ui_font_size * 1.5))
                    .child("Open"),
            )
            .into_any_element()
    }
}

/// Opens a window (the app id `binbun` names its `.desktop` entry, so
/// Wayland compositors find its icon), on `path` if given, else on the
/// start page; whether it opened.
pub fn open_window(path: Option<&Path>, cx: &mut gpui_kit::App) -> bool {
    let bounds = gpui_kit::Bounds::centered(None, size(px(1600.0), px(1000.0)), cx);
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        app_id: Some("binbun".to_owned()),
        ..gpui_kit::component::TitleBar::window_options()
    };
    let opened = gpui_kit::open_window(options, cx, |window, cx| {
        cx.new(|cx| Workspace::new(path.map(Path::to_path_buf), window, cx))
    });
    match opened {
        Ok((handle, workspace)) => {
            register_window(handle, &workspace, cx);
            true
        }
        Err(error) => {
            eprintln!("cannot open a window: {error}");
            false
        }
    }
}
