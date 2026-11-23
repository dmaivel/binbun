//! Checks that the C binbun prints does what the machine code does
//! (differential interpretation from random and shaped states), for every
//! function on all cores: one line per function that differs, then the
//! verdicts counted.
//!
//! With no file given it runs on the checked-in test program
//! (`tests/fixtures/program-x86_64.elf`); give a path to run on your own
//! binary.
//!
//! ```text
//! cargo run --release -p binbun --example verify
//! cargo run --release -p binbun --example verify -- /usr/bin/true
//! ```

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::process::ExitCode;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::threads;
use binbun::queries::verify::{Difference, Options, Verdict, verify_all};
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
            eprintln!("usage: verify [FILE]");
            return ExitCode::FAILURE;
        }
    };
    match verify(path) {
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

/// The functions of the binary at `path` whose C differs, then the count
/// of each verdict.
fn verify(path: &str) -> Result<Vec<String>, String> {
    let data = fs::read(path).map_err(|error| error.to_string())?;
    let image = Image::parse(&data).map_err(|error| error.to_string())?;
    let database = Database::new(&image, Seeds::ALL).map_err(|error| error.to_string())?;
    let mut verifications = Vec::new();
    verify_all(&database, &Options::default(), threads(), |v| {
        verifications.push(v);
    });
    verifications.sort_by_key(|v| v.entry);

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut lines = Vec::new();
    for v in &verifications {
        let verdict = match &v.verdict {
            Verdict::Agreed(_) => "agreed",
            Verdict::NotCheckable(_) => "not_checkable",
            Verdict::Differs(difference) => {
                let why = match difference {
                    Difference::Structure(mismatch) => mismatch.to_string(),
                    Difference::Run(counterexample) => counterexample.message.clone(),
                };
                let name = database
                    .data_name(v.entry)
                    .unwrap_or_else(|| format!("sub_{:X}", v.entry));
                lines.push(format!("{:#010x} {name}: {why}", v.entry));
                "differs"
            }
        };
        *counts.entry(verdict).or_default() += 1;
    }
    lines.extend(
        counts
            .iter()
            .map(|(verdict, count)| format!("{verdict}: {count}")),
    );
    Ok(lines)
}
