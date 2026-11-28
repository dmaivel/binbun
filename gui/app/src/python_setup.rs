//! binbun's Python (`binbun_gui_view::python_env`), checked when something
//! needs it (the console shown, a coding agent started in a terminal): the
//! Python the settings name, once for each it names, off the UI thread.
//! One that cannot run binbun gets a banner: Set Up Python makes binbun an
//! environment of its own (a venv in its data folder, `binbun` of the
//! app's version from the Python Package Index) and names it in the
//! settings, which the
//! console and an agent's `binbun mcp` then run; Choose Python… opens the
//! settings.

use binbun_gui_view::banners::{Action, Banner, Button, Kind, Priority, Tone};
use binbun_gui_view::commands::Command;
use binbun_gui_view::python_env;
use binbun_gui_view::settings::Setting;
use binbun_paths::Place;
use gpui_kit::{Context, Window};

use crate::workspace::Workspace;

/// The `binbun` package installed: the app's version (one for everything).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// binbun's Python as the window has checked it.
#[derive(Debug, Default)]
pub struct PythonUi {
    /// The interpreter checked last, and what was found.
    checked: Option<(String, Check)>,
    /// binbun's environment being made, or how that went.
    setup: Option<Setup>,
}

/// What checking an interpreter found.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Check {
    Running,
    Ready,
    /// Why it cannot run binbun.
    Broken(String),
}

/// Making binbun's environment.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Setup {
    Running,
    /// Made: its Python, now the setting's.
    Done(String),
    /// Failed, saying this.
    Failed(String),
}

impl Workspace {
    /// Checks the Python the settings name, unless it was (something needs
    /// it now).
    pub fn check_python(&mut self, cx: &mut Context<Self>) {
        let interpreter = self.settings.python_interpreter.clone();
        if self
            .python
            .checked
            .as_ref()
            .is_some_and(|(checked, _)| *checked == interpreter)
        {
            return;
        }
        self.python.checked = Some((interpreter.clone(), Check::Running));
        let checked = interpreter.clone();
        let task = cx
            .background_executor()
            .spawn(async move { python_env::check(&checked) });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            let _ = this.update(cx, |this, cx| {
                if let Some((now, check)) = &mut this.python.checked
                    && *now == interpreter
                {
                    *check = match result {
                        Ok(()) => Check::Ready,
                        Err(why) => Check::Broken(why),
                    };
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// The banner of binbun's Python: the setup running or how it went,
    /// else the Python the settings name unable to run binbun.
    pub fn python_banner(&self) -> Option<Banner> {
        let banner = |tone, text: String, buttons, closable| Banner {
            kind: Kind::Python,
            priority: Priority::Failure,
            about: text.clone(),
            text,
            tone,
            buttons,
            closable,
        };
        let choose = || Button {
            label: "Choose Python\u{2026}".to_owned(),
            action: Action::Command(Command::Settings),
        };
        match &self.python.setup {
            Some(Setup::Running) => {
                return Some(banner(
                    Tone::Busy,
                    format!(
                        "Setting up Python for binbun: a venv, binbun {VERSION} from PyPI\u{2026}"
                    ),
                    Vec::new(),
                    false,
                ));
            }
            Some(Setup::Failed(why)) => {
                return Some(banner(
                    Tone::Error,
                    format!("Setting up Python for binbun failed: {why}"),
                    vec![choose()],
                    true,
                ));
            }
            Some(Setup::Done(python)) => {
                return Some(banner(
                    Tone::Info,
                    format!("binbun's Python is set up: {python}"),
                    Vec::new(),
                    true,
                ));
            }
            None => {}
        }
        let Some((_, Check::Broken(why))) = &self.python.checked else {
            return None;
        };
        Some(banner(
            Tone::Error,
            format!("binbun's Python isn't set up: {why}."),
            vec![
                Button {
                    label: "Set Up Python".to_owned(),
                    action: Action::SetUpPython,
                },
                choose(),
            ],
            true,
        ))
    }

    /// The banner's Set Up Python: binbun's environment made off the UI
    /// thread, then named in the settings.
    pub fn set_up_python(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(dir) = Place::PythonEnv.path() else {
            self.python.setup = Some(Setup::Failed(Place::PythonEnv.missing()));
            return;
        };
        self.python.setup = Some(Setup::Running);
        let task = cx
            .background_executor()
            .spawn(async move { python_env::make_env(&dir, VERSION) });
        cx.spawn_in(window, async move |this, cx| {
            let result = task.await;
            let _ = this.update_in(cx, |this, window, cx| {
                match result {
                    Ok(python) => {
                        let python = python.to_string_lossy().into_owned();
                        this.set_setting(
                            "python.interpreter",
                            &Setting::Text(python.clone()),
                            window,
                            cx,
                        );
                        this.python.checked =
                            Some((this.settings.python_interpreter.clone(), Check::Ready));
                        this.python.setup = Some(Setup::Done(python));
                    }
                    Err(why) => this.python.setup = Some(Setup::Failed(why)),
                }
                cx.notify();
            });
        })
        .detach();
    }
}
