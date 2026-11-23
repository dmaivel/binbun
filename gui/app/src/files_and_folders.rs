//! binbun's folders in the window (`binbun_paths`): Help → Files and
//! Folders lists each with its path (or why it has none) and its size,
//! counted off the UI thread, and reveals it in the file manager; File →
//! Reveal Projects opens the projects folder. A folder revealed is made
//! first if it is not there.

use std::path::Path;

use binbun_gui_view::commands::Command;
use binbun_paths::{Folder, Place, size_text};
use gpui_kit::prelude::*;
use gpui_kit::{AnyElement, ClickEvent, Context, MouseButton, Task, Window, div};

use crate::sidebar::tabular;
use crate::theme::hsla;
use crate::workspace::{ICON_BUTTON, Workspace};

/// Files and Folders' overlay.
#[derive(Default)]
pub struct FilesAndFoldersUi {
    /// The folders shown (`None`: closed), with their sizes once counted.
    folders: Option<Vec<Folder>>,
    /// The count running.
    count: Option<Task<()>>,
}

impl FilesAndFoldersUi {
    /// Whether the overlay is open.
    pub const fn is_open(&self) -> bool {
        self.folders.is_some()
    }

    /// Closes the overlay (its count with it); whether it was open.
    pub fn close(&mut self) -> bool {
        self.count = None;
        self.folders.take().is_some()
    }
}

impl Workspace {
    /// Runs the folders' `command`; whether it was one.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "the folders take two of the registry's commands; `run` the rest"
    )]
    pub fn folders_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        match command {
            Command::FilesAndFolders => self.open_files_and_folders(window, cx),
            Command::RevealProjects => match Place::Projects.path() {
                Some(dir) => self.reveal(&dir, cx),
                None => self.error = Some(Place::Projects.missing()),
            },
            _ => return false,
        }
        true
    }

    /// Opens `dir` in the file manager, made first if it is not there
    /// (and tagged if in binbun's cache); what fails is said.
    pub fn reveal(&mut self, dir: &Path, cx: &mut Context<Self>) {
        if let Err(error) = std::fs::create_dir_all(dir) {
            self.error = Some(format!("{}: {error}", dir.display()));
            return;
        }
        if let Err(error) = binbun_paths::tag_cache(dir) {
            self.error = Some(format!("{}: {error}", dir.display()));
        }
        cx.open_with_system(dir);
    }

    /// Opens the overlay, which takes the focus: the folders at once,
    /// their sizes once counted off the UI thread.
    fn open_files_and_folders(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.close_overlays(window, cx);
        self.files_and_folders.folders = Some(binbun_paths::folders(false));
        let counted = cx
            .background_executor()
            .spawn(async { binbun_paths::folders(true) });
        self.files_and_folders.count = Some(cx.spawn_in(window, async move |this, cx| {
            let folders = counted.await;
            let _ = this.update_in(cx, |this, _, cx| {
                let ui = &mut this.files_and_folders;
                ui.count = None;
                if ui.is_open() {
                    ui.folders = Some(folders);
                    cx.notify();
                }
            });
        }));
        window.focus(&self.overlay_focus, cx);
        cx.notify();
    }

    /// The overlay, if open: a line a folder, its name, its path (why it
    /// has none, muted), its size and Reveal.
    pub fn render_files_and_folders(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let folders = self.files_and_folders.folders.as_ref()?;
        let theme = self.theme;
        let muted = hsla(theme.text_muted);
        let rows: Vec<_> = folders
            .iter()
            .enumerate()
            .map(|(i, folder)| {
                let place = folder
                    .path
                    .as_ref()
                    .map_or_else(|| folder.dir.missing(), |path| path.display().to_string());
                let size = folder
                    .path
                    .as_ref()
                    .and(folder.size)
                    .map(size_text)
                    .unwrap_or_default();
                let reveal = folder.path.clone().map(|path| {
                    div()
                        .id(("reveal-folder", i))
                        .flex()
                        .items_center()
                        .h(self.z(ICON_BUTTON))
                        .px(self.z(10.0))
                        .rounded(self.z(4.0))
                        .hover(|s| s.bg(hsla(theme.element_hover)))
                        .cursor_pointer()
                        .on_mouse_down(MouseButton::Left, |_, window, cx| {
                            window.prevent_default();
                            cx.stop_propagation();
                        })
                        .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                            this.reveal(&path, cx);
                            cx.notify();
                        }))
                        .child("Reveal")
                });
                div()
                    .flex()
                    .items_center()
                    .gap(self.z(12.0))
                    .h(self.z(ICON_BUTTON + 4.0))
                    .child(div().flex_none().w(self.z(56.0)).child(folder.dir.name()))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_ellipsis()
                            .when(folder.path.is_none(), |d| d.text_color(muted))
                            .child(place),
                    )
                    .child(
                        div()
                            .flex_none()
                            .flex()
                            .justify_end()
                            .w(self.z(64.0))
                            .text_color(muted)
                            .font_features(tabular())
                            .child(size),
                    )
                    .child(
                        div()
                            .flex_none()
                            .flex()
                            .justify_end()
                            .w(self.z(64.0))
                            .children(reveal),
                    )
            })
            .collect();
        Some(
            div()
                .id("files-and-folders")
                .track_focus(&self.overlay_focus)
                .px(self.z(12.0))
                .py(self.z(8.0))
                .flex()
                .flex_col()
                .text_color(hsla(theme.text))
                .children(rows)
                .into_any_element(),
        )
    }
}
