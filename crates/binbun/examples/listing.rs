//! Builds the listing of a file and prints what it holds, or lines.
//!
//! `cargo run --release -p binbun --example listing -- FILE`
//! prints the time and memory the line space takes and its counts (every
//! line rendered once); with `ADDRESS [LINES]` (hexadecimal), the lines
//! from the one holding `ADDRESS` instead; with `--all`, every line.

#![allow(clippy::unwrap_used, reason = "a command-line example fails loudly")]

use std::time::Instant;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::listing::{LineKind, Listing, Options, Role};
use binbun_loader::Image;

/// `/proc/self/status`'s `field` in KiB.
fn status_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(field))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

fn resident_kib() -> u64 {
    status_kib("VmRSS:")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .expect("usage: listing FILE [ADDRESS [LINES] | --all]");
    let data = std::fs::read(path).unwrap();
    let image = Image::parse(&data).unwrap();
    let db = Database::new(&image, Seeds::ALL).unwrap();
    let references = Instant::now();
    db.references();
    let references = references.elapsed();
    let before = resident_kib();
    let start = Instant::now();
    let listing = Listing::build(&db, &Options::default());
    let built = start.elapsed();
    let after = resident_kib();
    match args.get(2).map(String::as_str) {
        Some("--all") => {
            for n in 0..listing.len() {
                println!("{}", listing.render(&db, n).text());
            }
        }
        Some(address) => {
            let address = u64::from_str_radix(address.trim_start_matches("0x"), 16).unwrap();
            let count: u64 = args.get(3).map_or(40, |n| n.parse().unwrap());
            let first = listing.line_of(address);
            // From the item's first line (its header and labels).
            let head = listing.line(first).unwrap().address;
            let mut n = first;
            while n > 0 && listing.line(n - 1).is_some_and(|l| l.address == head) {
                n -= 1;
            }
            for n in n..(n + count).min(listing.len()) {
                println!("{}", listing.render(&db, n).text());
            }
        }
        None => {
            let render = Instant::now();
            let (mut symbolised, mut instructions) = (0u64, 0u64);
            for n in 0..listing.len() {
                let rendered = listing.render(&db, n);
                if listing.line(n).unwrap().kind == LineKind::Instruction {
                    instructions += 1;
                    symbolised += rendered
                        .tokens
                        .iter()
                        .filter(|t| {
                            matches!(
                                t.role,
                                Role::CodeName
                                    | Role::DataName
                                    | Role::ImportName
                                    | Role::LocalName
                            )
                        })
                        .count() as u64;
                }
            }
            let stats = listing.stats();
            println!(
                "{path}: references {:.2} s; line space {:.3} s, RSS +{} MiB ({} MiB, peak {} MiB); \
                 {} lines, {} instructions, {} data items, {} dummy names, {} string names; \
                 rendering every line {:.2} s: {} operands symbolised in {} instructions",
                references.as_secs_f64(),
                built.as_secs_f64(),
                after.saturating_sub(before) / 1024,
                after / 1024,
                status_kib("VmHWM:") / 1024,
                stats.lines,
                stats.instructions,
                stats.data_items,
                stats.dummy_names,
                stats.string_names,
                render.elapsed().as_secs_f64(),
                symbolised,
                instructions,
            );
        }
    }
}
