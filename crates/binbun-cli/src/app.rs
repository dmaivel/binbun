//! Windows: the release zip's two executables. `binbun.exe` at the top is
//! the app (a GUI program: no console window), `bin\binbun.exe` the
//! commands alone (a console program: shells wait for it and show its
//! output). Asked for the GUI (no command, or a file alone), the commands
//! start the app with the same arguments and return at once.

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

/// `DETACHED_PROCESS`: the app gets no console, not even this one.
const DETACHED_PROCESS: u32 = 0x0000_0008;
/// `CREATE_NEW_PROCESS_GROUP`: Ctrl+C in this console never reaches it.
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// The app beside this executable: `binbun.exe` in the folder above its
/// own (the release zip's layout), if there is one.
pub(crate) fn path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let app = exe.parent()?.parent()?.join("binbun.exe");
    app.is_file().then_some(app)
}

/// Starts `app` with `file` (else the start page), detached: this
/// process returns at once. Its standard streams are none of this
/// process's, so a pipe from this command ends when this command does.
pub(crate) fn open(app: &Path, file: Option<&Path>) -> ExitCode {
    let started = Command::new(app)
        .args(file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn();
    match started {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("binbun: {}: {error}", app.display());
            ExitCode::FAILURE
        }
    }
}
