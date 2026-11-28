//! binbun's Python: whether the interpreter the settings name
//! (`python.interpreter`, the console's and the agents' `binbun mcp`'s)
//! runs binbun's Python side, and an environment binbun makes for itself
//! when it cannot ([`binbun_paths::Place::PythonEnv`]): a venv of the
//! user's Python 3.11 or newer, the `binbun` package of the app's version
//! installed in it from the Python Package Index. A system Python usually
//! refuses packages
//! installed into it (PEP 668), so a venv is the way.
//!
//! Everything here blocks: the GUI runs it off its UI thread.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The oldest Python binbun's package takes.
const OLDEST: (u32, u32) = (3, 11);

/// What [`check`] runs: the version, then the package.
const CHECK: &str = "import sys\n\
if sys.version_info < (3, 11): sys.exit('Python 3.11 or newer is needed, not ' + sys.version.split()[0])\n\
import binbun\n";

/// Whether `interpreter` (a path, `~/` the home, or a name on `PATH`) runs
/// binbun's Python side.
///
/// # Errors
///
/// Why not, said for a banner: no Python there, too old, or no `binbun`
/// package in it.
pub fn check(interpreter: &str) -> Result<(), String> {
    let out = command(&program(interpreter))
        .args(["-c", CHECK])
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!("there is no Python at {interpreter}")
            } else {
                format!("{interpreter} could not be started: {e}")
            }
        })?;
    if out.status.success() {
        return Ok(());
    }
    let said = last_said(&out);
    if said.contains("No module named") && said.contains("binbun") {
        Err(format!("{interpreter} has no binbun package"))
    } else {
        Err(format!("{interpreter}: {said}"))
    }
}

/// The interpreter `interpreter` names: `~/` expanded, else as it is.
pub fn program(interpreter: &str) -> PathBuf {
    let interpreter = interpreter.trim();
    match (interpreter.strip_prefix("~/"), binbun_paths::home()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(interpreter),
    }
}

/// The Python of the environment at `dir`.
pub fn env_python(dir: &Path) -> PathBuf {
    if cfg!(windows) {
        dir.join("Scripts").join("python.exe")
    } else {
        dir.join("bin").join("python")
    }
}

/// binbun's environment made (or brought up to date) at `dir` from the
/// first Python 3.11 or newer on `PATH` with `venv`, `binbun` `version`
/// installed in it from the Python Package Index and checked. Its Python.
///
/// # Errors
///
/// Which step failed and the last line it wrote: no Python, no `venv`
/// (Debian's `python3-venv`), `pip` (no network, no such version).
pub fn make_env(dir: &Path, version: &str) -> Result<PathBuf, String> {
    let base = base_python().ok_or_else(|| {
        format!(
            "no Python {}.{} or newer with venv on PATH (python3, python): install one, \
             or choose a Python with binbun in the Python setting",
            OLDEST.0, OLDEST.1
        )
    })?;
    let mut venv = command(&base.0);
    venv.args(&base.1).arg("-m").arg("venv").arg(dir);
    run(&mut venv).map_err(|said| format!("making the environment: {said}"))?;
    let python = env_python(dir);
    let mut pip = command(&python);
    pip.args([
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--upgrade",
    ])
    .arg(format!("binbun=={version}"));
    run(&mut pip).map_err(|said| format!("installing binbun {version}: {said}"))?;
    check(&python.to_string_lossy())?;
    Ok(python)
}

/// The first Python 3.11 or newer on `PATH` that has `venv`: its program
/// and the arguments that pick it (Windows' `py -3`).
fn base_python() -> Option<(PathBuf, Vec<&'static str>)> {
    let probe = format!("import sys, venv\nsys.exit(0 if sys.version_info >= {OLDEST:?} else 1)");
    let mut candidates: Vec<(PathBuf, Vec<&'static str>)> = vec![
        (PathBuf::from("python3"), Vec::new()),
        (PathBuf::from("python"), Vec::new()),
    ];
    if cfg!(windows) {
        candidates.push((PathBuf::from("py"), vec!["-3"]));
    }
    candidates.into_iter().find(|(program, args)| {
        command(program)
            .args(args)
            .args(["-c", &probe])
            .output()
            .is_ok_and(|out| out.status.success())
    })
}

/// `program` run with nothing on its standard input (and on Windows no
/// console window flashing up).
fn command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command.stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        /// No console window for it.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// `command` run to its end: the last line it wrote if it failed.
fn run(command: &mut Command) -> Result<(), String> {
    let out = command.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(last_said(&out))
    }
}

/// The last line a failed program wrote (its error's, else its
/// output's), else how it ended.
pub fn last_said(out: &Output) -> String {
    [&out.stderr, &out.stdout]
        .into_iter()
        .find_map(|bytes| {
            String::from_utf8_lossy(bytes)
                .lines()
                .rev()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| out.status.to_string())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A Python without binbun is said to lack it; a program that is not
    /// there is said to be missing.
    #[test]
    fn a_python_without_binbun_is_said_so() {
        let python = base_python().map(|(program, _)| program);
        if let Some(python) = python {
            let python = python.to_string_lossy().into_owned();
            let said = check(&python);
            // This machine's Python may have binbun; then it is fine.
            if let Err(said) = said {
                assert!(said.contains("has no binbun package"), "{said}");
            }
        }
        assert_eq!(
            check("/nonexistent/python"),
            Err("there is no Python at /nonexistent/python".to_owned())
        );
    }
}
