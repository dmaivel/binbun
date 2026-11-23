//! The `binbun` command ([`main`]): both of binbun's builds run it, the
//! root workspace's `binbun` (the commands alone, for servers and CI: no
//! GPUI, no window system's libraries) and the GUI's (`gui/`), which
//! opens the GUI when given no command, or a file alone
//! ([`Invocation`]).
//! On Windows the release zip holds both: the app at the top, the
//! commands alone in `bin\`, which start the app beside them for what
//! opens the GUI.
//!
//! What the command adds to the engine ([`binbun`]): the compile
//! check of decompiled C, which runs the system's C compilers
//! ([`compile_check`]); the scorer of the
//! decompiler's types against debug information ([`score`], with why L2
//! has parameters and return values the source does not, [`extras`]).
//! `binbun update --check` ([`update`]).

#[cfg(windows)]
mod app;
mod commands;
pub mod extras;
pub mod provenance;
pub mod score;
pub mod update;

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicUsize, Ordering};

use commands::COMMANDS;

/// What `binbun`'s arguments ask for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invocation {
    /// The GUI: no arguments, or a file alone (opened in it).
    Gui(Option<PathBuf>),
    /// A command, its name first; or arguments that are none (a flag of
    /// no command's, a file with more after it), answered with the usage.
    Command(Vec<String>),
}

impl Invocation {
    /// What `args` (the program's name left out) ask for: a command when
    /// the first names one or is a flag (`--help`, `--version`), or when
    /// more than one is given; else the GUI, with the file given alone
    /// (`./run` opens a file named like a command).
    ///
    /// # Errors
    ///
    /// A command's argument is not Unicode.
    pub fn of(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut args: Vec<OsString> = args.into_iter().collect();
        if cfg!(target_os = "macos") {
            // The process serial number an app opened from the Finder may
            // be given (`-psn_0_123456`): no argument of the user's.
            args.retain(|arg| !arg.to_str().is_some_and(|arg| arg.starts_with("-psn_")));
        }
        match args.as_slice() {
            [] => Ok(Self::Gui(None)),
            [file] if !is_command(file) => Ok(Self::Gui(Some(PathBuf::from(file)))),
            _ => args
                .into_iter()
                .map(|arg| {
                    arg.into_string()
                        .map_err(|arg| format!("binbun: {} is not Unicode", arg.display()))
                })
                .collect::<Result<_, _>>()
                .map(Self::Command),
        }
    }
}

/// Whether the first argument `word` names a command or is a flag (a
/// flag never a file to open, Unicode or not).
fn is_command(word: &OsStr) -> bool {
    word.as_encoded_bytes().starts_with(b"-")
        || word.to_str().is_some_and(|word| COMMANDS.contains(&word))
}

/// The GUI, given the file to open: what the GUI's build passes to
/// [`main`].
pub type Gui = fn(Option<PathBuf>) -> ExitCode;

/// `binbun` with this process's arguments ([`Invocation::of`]): a command
/// run here, the GUI by `gui`; a binbun built without the GUI (`None`)
/// asked for it starts the app on Windows when it is in the folder above
/// (the release zip's `bin\binbun.exe`), else says so and gives the
/// usage.
pub fn main(gui: Option<Gui>) -> ExitCode {
    match Invocation::of(std::env::args_os().skip(1)) {
        Ok(Invocation::Command(args)) => commands::command(&args, opens_gui(gui)),
        Ok(Invocation::Gui(file)) => match gui {
            Some(gui) => gui(file),
            None => without_gui(file.as_deref()),
        },
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// Whether `binbun [FILE]` opens the GUI: the GUI's build does, and on
/// Windows the commands alone do when the app is beside them
/// (`app::path`).
fn opens_gui(gui: Option<Gui>) -> bool {
    #[cfg(windows)]
    if gui.is_none() {
        return app::path().is_some();
    }
    gui.is_some()
}

/// A binbun built without the GUI, asked for it: on Windows the app
/// beside it started (`app::path`), else it says so.
fn without_gui(file: Option<&Path>) -> ExitCode {
    #[cfg(windows)]
    if let Some(app) = app::path() {
        return app::open(&app, file);
    }
    commands::without_gui(file)
}

/// One compiler's verdict on a C file ([`compile_check`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The compiler (`gcc`, `clang`).
    pub compiler: &'static str,
    /// Errors (a failed compilation without one counts one).
    pub errors: usize,
    /// Warnings.
    pub warnings: usize,
    /// What it printed.
    pub diagnostics: String,
}

/// The compilers [`compile_check`] runs.
pub const COMPILERS: [&str; 2] = ["gcc", "clang"];

/// The flags: C11, wrapping signed arithmetic, no type-based
/// aliasing, every common warning, compile only.
pub const FLAGS: [&str; 6] = [
    "-std=c11",
    "-fwrapv",
    "-fno-strict-aliasing",
    "-Wall",
    "-fdiagnostics-color=never",
    "-c",
];

/// Distinguishes the directories of checks run at once in one process.
static CHECKS: AtomicUsize = AtomicUsize::new(0);

/// Compiles `source` with each of [`COMPILERS`] that is installed, with
/// [`FLAGS`], `headers` (name, contents) beside it, in a directory of its
/// own under `~/.cache/binbun-print-check/` (removed afterwards): each
/// compiler's errors and warnings. A compiler that is not installed is
/// left out.
///
/// # Errors
///
/// `HOME` is not set, or the directory or files cannot be written, or a
/// compiler cannot be run for another reason than its absence.
pub fn compile_check(source: &str, headers: &[(&str, &str)]) -> io::Result<Vec<Verdict>> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    let directory = PathBuf::from(home)
        .join(".cache/binbun-print-check")
        .join(format!(
            "{}-{}",
            std::process::id(),
            CHECKS.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&directory)?;
    let verdicts = compile_in(&directory, source, headers);
    let removed = std::fs::remove_dir_all(&directory);
    let verdicts = verdicts?;
    removed?;
    Ok(verdicts)
}

/// [`compile_check`] in `directory`.
fn compile_in(
    directory: &Path,
    source: &str,
    headers: &[(&str, &str)],
) -> io::Result<Vec<Verdict>> {
    for (name, contents) in headers {
        std::fs::write(directory.join(name), contents)?;
    }
    let file = directory.join("function.c");
    std::fs::write(&file, source)?;
    let mut verdicts = Vec::new();
    for compiler in COMPILERS {
        let output = match Command::new(compiler)
            .args(FLAGS)
            .arg("-o")
            .arg(directory.join(format!("{compiler}.o")))
            .arg(&file)
            .current_dir(directory)
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let diagnostics = String::from_utf8_lossy(&output.stderr).into_owned();
        // A diagnostic's own line starts at its location; the source lines
        // quoted under it are indented (`   39 |     f("error: ");`).
        let count = |kind: &str| {
            diagnostics
                .lines()
                .filter(|line| !line.starts_with(' ') && line.contains(kind))
                .count()
        };
        let errors = count(" error: ") + count(" fatal error: ");
        let errors = if output.status.success() {
            errors
        } else {
            errors.max(1)
        };
        verdicts.push(Verdict {
            compiler,
            errors,
            warnings: count(" warning: "),
            diagnostics,
        });
    }
    Ok(verdicts)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::Invocation;

    fn of(args: &[&str]) -> Invocation {
        Invocation::of(args.iter().map(OsString::from)).unwrap()
    }

    fn command(args: &[&str]) -> Invocation {
        Invocation::Command(args.iter().map(|&arg| arg.to_owned()).collect())
    }

    #[test]
    fn nothing_or_a_file_alone_opens_the_gui() {
        assert_eq!(of(&[]), Invocation::Gui(None));
        for file in ["/usr/bin/bash", "bash", "./run", "C:\\a b\\x.exe"] {
            assert_eq!(of(&[file]), Invocation::Gui(Some(PathBuf::from(file))));
        }
    }

    #[test]
    fn a_command_or_a_flag_first_or_more_than_a_file_is_a_command() {
        for args in [
            &["run"][..],
            &["decompile", "/usr/bin/bash", "main"],
            &["update", "--check"],
            &["help"],
            &["--help"],
            &["-h"],
            &["--version"],
            &["-V"],
            // Answered with the usage.
            &["--nonsense"],
            &["-x"],
            &["-"],
            &["functions"],
            &["decompile"],
            &["/usr/bin/bash", "main"],
        ] {
            assert_eq!(of(args), command(args), "{args:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_file_needs_no_unicode_name_but_a_command_unicode_arguments() {
        use std::os::unix::ffi::OsStringExt;
        let file = OsString::from_vec(b"bin\xffary".to_vec());
        assert_eq!(
            Invocation::of([file.clone()]).unwrap(),
            Invocation::Gui(Some(PathBuf::from(&file)))
        );
        assert!(Invocation::of([OsString::from("functions"), file]).is_err());
        // A flag is no file, whatever its bytes.
        assert!(Invocation::of([OsString::from_vec(b"-\xff".to_vec())]).is_err());
    }
}
