//! Opens an executable and lists its functions: entry, blocks, whether
//! they return, and name, in address order. The engine's first step: the
//! image parsed, its functions recovered.
//!
//! With no file given it runs on the checked-in test program
//! (`tests/fixtures/program-x86_64.elf`); give a path to run on your own
//! binary.
//!
//! ```text
//! cargo run --release -p binbun --example list_functions
//! cargo run --release -p binbun --example list_functions -- /usr/bin/true
//! ```

use std::env;
use std::fs;
use std::process::ExitCode;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun_loader::Image;

/// The binary run on when no file is given.
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/program-x86_64.elf"
);

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let path = match args.as_slice() {
        [] => FIXTURE,
        [path] => path.as_str(),
        _ => {
            eprintln!("usage: list_functions [FILE]");
            return ExitCode::FAILURE;
        }
    };
    match list(path) {
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

/// A header, then one line per function of the binary at `path`.
fn list(path: &str) -> Result<Vec<String>, String> {
    let data = fs::read(path).map_err(|error| error.to_string())?;
    let image = Image::parse(&data).map_err(|error| error.to_string())?;
    let database = Database::new(&image, Seeds::ALL).map_err(|error| error.to_string())?;
    let mut functions: Vec<_> = database.functions().map(|(_, f)| f).collect();
    functions.sort_by_key(|f| f.entry);
    let mut lines = vec![
        format!("{path}: {} functions", functions.len()),
        format!("{:>10}  {:>6}  {:<8}  name", "entry", "blocks", "returns"),
    ];
    for function in functions {
        // The image's name (a symbol, an import's thunk), else binbun's.
        let name = database
            .data_name(function.entry)
            .unwrap_or_else(|| format!("sub_{:X}", function.entry));
        let returns = if function.returns { "yes" } else { "no" };
        lines.push(format!(
            "{:#010x}  {:>6}  {returns:<8}  {name}",
            function.entry,
            function.blocks.len()
        ));
    }
    Ok(lines)
}
