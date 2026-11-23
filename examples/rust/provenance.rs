//! Decompiles a function with provenance: opens a binary as a front end
//! does (a `binbun-session` session, nothing saved), waits for its
//! functions, and prints the function's C with, after each line, the
//! addresses of the machine instructions it came from.
//!
//! With no arguments it decompiles main in the checked-in test program
//! (`tests/fixtures/program-x86_64.elf`); give a path, and a function
//! (default main), to run on your own binary.
//!
//! ```text
//! cargo run --release -p binbun-session --example provenance
//! cargo run --release -p binbun-session --example provenance -- /usr/bin/bash main
//! ```

use std::env;
use std::process::ExitCode;

use binbun_session::{Options, Session, Stage, Waited};

/// The binary run on when no file is given.
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/program-x86_64.elf"
);

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (path, name) = match args.as_slice() {
        [] => (FIXTURE, "main"),
        [path] => (path.as_str(), "main"),
        [path, name] => (path.as_str(), name.as_str()),
        _ => {
            eprintln!("usage: provenance [FILE [FUNCTION]]");
            return ExitCode::FAILURE;
        }
    };
    match lines(path, name) {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{path}: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Each line of the C of `name` in the binary at `path`, with its
/// instructions' addresses after it.
fn lines(path: &str, name: &str) -> Result<Vec<String>, String> {
    let options = Options {
        ephemeral: true,
        ..Options::default()
    };
    let session = Session::open(path, options).map_err(|error| error.to_string())?;
    match session.wait(Stage::Analysed, None) {
        Waited::Reached(_) => {}
        Waited::TimedOut(stage)
        | Waited::Stopped {
            stage,
            failure: None,
        } => {
            return Err(format!("stopped at {stage:?}"));
        }
        Waited::Stopped {
            failure: Some(failure),
            ..
        } => return Err(failure),
    }
    let database = session.database().ok_or("no functions")?;
    let function = database.find_function(name)?;
    let document = session.document(function)?;
    let lines = document
        .lines()
        .iter()
        .enumerate()
        .map(|(n, line)| {
            let made: Vec<String> = line.addresses.iter().map(|a| format!("{a:#x}")).collect();
            if made.is_empty() {
                document.line_text(n).to_owned()
            } else {
                format!("{:<60} // {}", document.line_text(n), made.join(" "))
            }
        })
        .collect();
    session.close();
    Ok(lines)
}
