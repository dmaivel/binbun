//! `falcon-functions FILE OUT`: Falcon's recursive function recovery
//! (`Loader::program_recursive`) on an ELF or PE file. Writes `=` (Falcon
//! uses the file's own addresses), then every function's start, in hex,
//! one per line.

use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use falcon::loader::{Elf, Loader, Pe};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, file, out] = &args[..] else {
        eprintln!("usage: falcon-functions FILE OUT");
        return ExitCode::FAILURE;
    };
    match run(Path::new(file), Path::new(out)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{file}: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(file: &Path, out: &Path) -> Result<(), String> {
    let magic = std::fs::read(file).map_err(|e| e.to_string())?;
    let loader: Box<dyn Loader> = if magic.starts_with(b"\x7fELF") {
        Box::new(Elf::from_file(file).map_err(|e| e.to_string())?)
    } else {
        Box::new(Pe::from_file(file).map_err(|e| e.to_string())?)
    };
    let program = loader.program_recursive().map_err(|e| e.to_string())?;
    let mut output = std::fs::File::create(out).map_err(|e| e.to_string())?;
    writeln!(output, "=").map_err(|e| e.to_string())?;
    for function in program.functions() {
        writeln!(output, "{:x}", function.address()).map_err(|e| e.to_string())?;
    }
    Ok(())
}
