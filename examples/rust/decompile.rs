//! Decompiles one function of a binary, as `binbun decompile FILE FUNCTION`
//! prints it: the image parsed, its functions recovered, the function
//! decompiled to C.
//!
//! With no arguments it decompiles main in the checked-in test program
//! (`tests/fixtures/program-x86_64.elf`); give a path, and a function
//! (default main), to run on your own binary.
//!
//! ```text
//! cargo run --release -p binbun --example decompile
//! cargo run --release -p binbun --example decompile -- /usr/bin/bash main
//! ```

use std::env;
use std::fs;
use std::process::ExitCode;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::Options;
use binbun_loader::Image;

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
            eprintln!("usage: decompile [FILE [FUNCTION]]");
            return ExitCode::FAILURE;
        }
    };
    match decompile(path, name) {
        Ok(c) => {
            println!("{c}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{path}: {message}");
            ExitCode::FAILURE
        }
    }
}

/// The C of the function named `name` (or at a hexadecimal address) in the
/// binary at `path`.
fn decompile(path: &str, name: &str) -> Result<String, String> {
    let data = fs::read(path).map_err(|error| error.to_string())?;
    let image = Image::parse(&data).map_err(|error| error.to_string())?;
    let database = Database::new(&image, Seeds::ALL).map_err(|error| error.to_string())?;
    let function = database.find_function(name)?;
    let options = Options {
        style: Some("kr".to_owned()),
        ..Options::default()
    };
    let decompiled = database.decompile(function, &options).result?;
    decompiled
        .c
        .map(|c| c.text)
        .ok_or_else(|| "no C was printed".to_owned())
}
