//! The binary's project in the window
//! (`binbun_gui_view::session::project`): kept in binbun's data directory
//! by the binary's contents. Export Project… writes it to one portable
//! file (`<name>.binbun`, a save dialog); Import Project…, or opening a
//! `.binbun` file, installs one as its binary's, asking first before it
//! replaces a project holding edits; the binary open, if it is that one,
//! is opened again with it. An export or import done says so once,
//! quietly, in the status bar.

use std::path::{Path, PathBuf};

use binbun_gui_view::commands::Command;
use binbun_gui_view::recent;
use binbun_gui_view::session::project::{self, Bundle, Key, Project};
use gpui_kit::prelude::*;
use gpui_kit::{AnyElement, ClickEvent, Context, MouseButton, Window, div};

use crate::start_page::unix_now;
use crate::theme::hsla;
use crate::workspace::{ICON_BUTTON, Workspace};

/// The project's state in the window.
#[derive(Default)]
pub struct ProjectsUi {
    /// What the status bar says, quietly, until the binary closes: an
    /// export or an import done.
    pub notice: Option<String>,
    /// The import waiting on its question (replace a project with edits?).
    pub question: Option<Replacing>,
    /// The open binary's project is known, and taken note of.
    known: bool,
}

/// An import that would replace a project holding edits.
pub struct Replacing {
    /// The exported project.
    bundle: Bundle,
    /// The projects directory it goes to.
    root: PathBuf,
    /// The project it replaces.
    project: Project,
}

impl ProjectsUi {
    /// A binary closed: what was said of it goes.
    pub fn closed(&mut self) {
        self.notice = None;
        self.known = false;
    }
}

impl Workspace {
    /// Runs the project's `command`; whether it was one.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "the project takes two of the registry's commands; `run` the rest"
    )]
    pub fn project_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        match command {
            Command::ExportProject => self.prompt_export(window, cx),
            Command::ImportProject => Self::prompt_import(window, cx),
            _ => return false,
        }
        true
    }

    /// Once the open binary's project is known (its image parsed): the
    /// recent files record it, opened, with its SHA-256 (the start page's
    /// edits mark) and the project it is open in (opened in it again), and
    /// a share's project's own edits are read. A file that fails to open
    /// is never recorded.
    pub fn project_known(&mut self) {
        let Some(session) = &self.session else {
            return;
        };
        if self.projects.known {
            return;
        }
        let Some(key) = session.key() else {
            return;
        };
        self.projects.known = true;
        let path =
            binbun_paths::canonical(session.path()).unwrap_or_else(|_| session.path().into());
        // Named in the projects directory, where Recent finds it again.
        let root = project::root();
        let dir = session
            .project()
            .map(Project::dir)
            .filter(|dir| {
                root.as_deref()
                    .is_some_and(|root| dir.parent() == Some(root))
            })
            .map(project::file_name);
        let list = recent::opened(&self.recent, &path, &key.hex(), dir.as_deref(), unix_now());
        self.set_recent(list);
        self.refresh_local();
    }

    /// Export Project…: a save dialog for `<name>.binbun` (in the home
    /// directory), then the project written there, its layout as it is now.
    fn prompt_export(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some((project, key)) = self
            .session
            .as_ref()
            .and_then(|s| Some((s.project()?.clone(), s.key()?.clone())))
        else {
            return;
        };
        self.save_layout();
        let home = binbun_paths::home().unwrap_or_else(|| PathBuf::from("."));
        let name = format!("{}.{}", key.name(), project::EXTENSION);
        let chosen = cx.prompt_for_new_path(&home, Some(&name));
        cx.spawn_in(window, async move |this, cx| {
            let chosen = chosen.await;
            let _ = this.update(cx, |this, cx| {
                match chosen {
                    Ok(Ok(Some(to))) => this.export_to(&project, &key, &to),
                    Ok(Err(error)) => this.error = Some(error.to_string()),
                    Ok(Ok(None)) | Err(_) => {}
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// Writes `project` (of the binary `key`) to `to`: not while the open
    /// session is still taking a freeze's changes out of its values, since
    /// the export copies them.
    fn export_to(&mut self, project: &Project, key: &Key, to: &Path) {
        if self
            .session
            .as_ref()
            .is_some_and(|session| !session.core().settled())
        {
            self.error = Some(
                "Changes a freeze withdrew are still being taken out of this project: try \
                 exporting again in a moment."
                    .to_owned(),
            );
            return;
        }
        match project::export(project, key, to) {
            Ok(()) => self.projects.notice = Some(format!("Exported {}", to.display())),
            Err(error) => self.error = Some(error),
        }
    }

    /// Import Project…: an open dialog, then the file imported.
    fn prompt_import(window: &mut Window, cx: &mut Context<Self>) {
        let paths = cx.prompt_for_paths(gpui_kit::PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: None,
        });
        cx.spawn_in(window, async move |this, cx| match paths.await {
            Ok(Ok(Some(paths))) => {
                if let Some(file) = paths.into_iter().next() {
                    let _ = this.update_in(cx, |this, window, cx| {
                        this.import_project(&file, window, cx);
                    });
                }
            }
            Ok(Err(error)) => {
                let _ = this.update(cx, |this, cx| {
                    this.error = Some(error.to_string());
                    cx.notify();
                });
            }
            Ok(Ok(None)) | Err(_) => {}
        })
        .detach();
    }

    /// Imports the exported project in `file` as its binary's: installed
    /// at once, unless a project holding edits is there (then asked).
    pub fn import_project(&mut self, file: &Path, window: &mut Window, cx: &mut Context<Self>) {
        let bundle = match Bundle::read(file) {
            Ok(bundle) => bundle,
            Err(error) => {
                self.error = Some(error);
                cx.notify();
                return;
            }
        };
        let Some(root) = project::root() else {
            self.error = Some(binbun_paths::Place::Projects.missing());
            cx.notify();
            return;
        };
        let project = bundle.project_in(&root);
        if project.has_edits() {
            self.close_overlays(window, cx);
            self.projects.question = Some(Replacing {
                bundle,
                root,
                project,
            });
            window.focus(&self.overlay_focus, cx);
        } else {
            self.install(&bundle, &root, window, cx);
        }
        cx.notify();
    }

    /// Installs `bundle` in `root`, replacing what is there; the binary
    /// open, if it is its, closed first (its edits and layout saved over
    /// by nothing after) and opened again with it.
    fn install(
        &mut self,
        bundle: &Bundle,
        root: &Path,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let reopen = self
            .session
            .as_ref()
            .filter(|s| s.key().is_some_and(|key| key.hex() == bundle.sha256()))
            .map(|s| s.path().to_path_buf());
        if reopen.is_some() {
            self.close_session();
        }
        let result = project::import(bundle, root, true);
        if let Some(path) = reopen {
            self.open(path, window, cx);
        }
        match result {
            Ok(_) => {
                self.projects.notice = Some(format!("Imported the project of {}", bundle.name()));
            }
            Err(error) => self.error = Some(error),
        }
    }

    /// Enter on the import's question: replaces the project; whether it
    /// was shown.
    pub fn answer_import_question(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        let Some(replacing) = self.projects.question.take() else {
            return false;
        };
        self.close_overlays(window, cx);
        self.install(&replacing.bundle, &replacing.root, window, cx);
        cx.notify();
        true
    }

    /// The import's question, if shown: the project it replaces; Enter
    /// replaces, Esc (or a click outside) does not.
    pub fn render_import_question(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let replacing = self.projects.question.as_ref()?;
        let theme = self.theme;
        let button = |id: &'static str, label: &'static str, default: bool| {
            div()
                .id(id)
                .flex()
                .items_center()
                .h(self.z(ICON_BUTTON))
                .px(self.z(10.0))
                .rounded(self.z(4.0))
                .text_color(hsla(theme.text))
                .when(default, |d| d.bg(hsla(theme.element_selected)))
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .on_mouse_down(MouseButton::Left, |_, window, cx| {
                    window.prevent_default();
                    cx.stop_propagation();
                })
                .child(label)
        };
        Some(
            div()
                .id("import-project")
                .track_focus(&self.overlay_focus)
                .p(self.z(12.0))
                .flex()
                .flex_col()
                .gap(self.z(4.0))
                .child(format!(
                    "Replace the project of {} and its edits?",
                    replacing.bundle.name()
                ))
                .child(
                    div()
                        .text_color(hsla(theme.text_muted))
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .text_ellipsis()
                        .child(replacing.project.dir().display().to_string()),
                )
                .child(
                    div()
                        .pt(self.z(8.0))
                        .flex()
                        .justify_end()
                        .gap(self.z(6.0))
                        .child(
                            button("import-cancel", "Cancel", false).on_click(cx.listener(
                                |this, _: &ClickEvent, window, cx| {
                                    this.close_overlays(window, cx);
                                    cx.notify();
                                },
                            )),
                        )
                        .child(
                            button("import-replace", "Replace", true).on_click(cx.listener(
                                |this, _: &ClickEvent, window, cx| {
                                    this.answer_import_question(window, cx);
                                },
                            )),
                        ),
                )
                .into_any_element(),
        )
    }
}
