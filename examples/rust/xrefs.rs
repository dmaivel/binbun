//! Cross-references of a function or an address: who refers to it (calls,
//! jumps, reads, writes, pointers in data), from where and in which
//! function; and, for a function, what it refers to.
//!
//! With no arguments it shows main's in the checked-in test program
//! (`tests/fixtures/program-x86_64.elf`); give a path, and a function or an
//! address (default main), to run on your own binary.
//!
//! ```text
//! cargo run --release -p binbun --example xrefs
//! cargo run --release -p binbun --example xrefs -- /usr/bin/true main
//! cargo run --release -p binbun --example xrefs -- program.elf 0x2004
//! ```

use std::env;
use std::fs;
use std::process::ExitCode;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::references::{Kind, Reference};
use binbun_loader::Image;

/// The binary run on when no file is given.
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/program-x86_64.elf"
);

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (path, target) = match args.as_slice() {
        [] => (FIXTURE, "main"),
        [path] => (path.as_str(), "main"),
        [path, target] => (path.as_str(), target.as_str()),
        _ => {
            eprintln!("usage: xrefs [FILE [NAME|ADDRESS]]");
            return ExitCode::FAILURE;
        }
    };
    match xrefs(path, target) {
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

/// The references to `target` in the binary at `path`, and those from it
/// if it is a function.
fn xrefs(path: &str, target: &str) -> Result<Vec<String>, String> {
    let data = fs::read(path).map_err(|error| error.to_string())?;
    let image = Image::parse(&data).map_err(|error| error.to_string())?;
    let database = Database::new(&image, Seeds::ALL).map_err(|error| error.to_string())?;
    // A function by the image's name for it (a symbol, an import's thunk),
    // else an address.
    let function = database
        .functions()
        .find(|(_, f)| database.data_name(f.entry).as_deref() == Some(target));
    let address = match function {
        Some((_, function)) => function.entry,
        None => target
            .strip_prefix("0x")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .ok_or_else(|| format!("no function {target}"))?,
    };
    let function = function.map(|(id, _)| id).or_else(|| {
        database
            .functions()
            .find(|(_, f)| f.entry == address)
            .map(|(id, _)| id)
    });
    let describe = |address: u64| match database.data_name(address) {
        Some(name) => format!("{address:#x} {name}"),
        None => format!("{address:#x}"),
    };
    let made_in = |reference: &Reference| {
        reference
            .function
            .and_then(|id| database.function(id))
            .map_or_else(
                || "(data)".to_owned(),
                |f| {
                    database
                        .data_name(f.entry)
                        .unwrap_or_else(|| format!("sub_{:X}", f.entry))
                },
            )
    };

    let references = database.references();
    let to = references.to(address);
    let mut lines = vec![format!("{} references to {}", to.len(), describe(address))];
    for reference in to {
        lines.push(format!(
            "  {:#010x}  {:<8}  in {}",
            reference.from,
            kind(reference.kind),
            made_in(reference)
        ));
    }
    if let Some(id) = function {
        let from: Vec<&Reference> = references.from_function(id).collect();
        lines.push(format!(
            "{} references from {}",
            from.len(),
            describe(address)
        ));
        for reference in from {
            lines.push(format!(
                "  {:#010x}  {:<8}  to {}",
                reference.from,
                kind(reference.kind),
                describe(reference.target)
            ));
        }
    }
    Ok(lines)
}

/// How a reference refers, in a word.
const fn kind(kind: Kind) -> &'static str {
    match kind {
        Kind::Call => "call",
        Kind::Jump => "jump",
        Kind::Read => "read",
        Kind::Write => "write",
        Kind::Address => "address",
        Kind::Pointer(_) => "pointer",
    }
}
