//! The signatures evaluation's word count in Rust
//! (scripts/signatures/corpus.sh): lines, words and bytes of each file or
//! standard input.

use std::env;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::process::ExitCode;

#[derive(Default, Clone, Copy)]
struct Counts {
    lines: u64,
    words: u64,
    bytes: u64,
}

fn count(mut input: impl Read) -> io::Result<Counts> {
    let mut counts = Counts::default();
    let mut buffer = [0u8; 8192];
    let mut in_word = false;
    loop {
        let got = input.read(&mut buffer)?;
        if got == 0 {
            return Ok(counts);
        }
        counts.bytes += got as u64;
        for &byte in &buffer[..got] {
            if byte == b'\n' {
                counts.lines += 1;
            }
            if byte.is_ascii_whitespace() {
                in_word = false;
            } else if !in_word {
                in_word = true;
                counts.words += 1;
            }
        }
    }
}

fn show(counts: Counts, name: Option<&str>) {
    let line = format!("{:7} {:7} {:7}", counts.lines, counts.words, counts.bytes);
    match name {
        Some(name) => println!("{line} {name}"),
        None => println!("{line}"),
    }
}

fn main() -> ExitCode {
    let names: Vec<String> = env::args().skip(1).collect();
    if names.is_empty() {
        return match count(io::stdin().lock()) {
            Ok(counts) => {
                show(counts, None);
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("wc: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let mut total = Counts::default();
    let mut failed = false;
    for name in &names {
        match File::open(name).map(BufReader::new).and_then(count) {
            Ok(counts) => {
                show(counts, Some(name));
                total.lines += counts.lines;
                total.words += counts.words;
                total.bytes += counts.bytes;
            }
            Err(error) => {
                eprintln!("wc: {name}: {error}");
                failed = true;
            }
        }
    }
    if names.len() > 1 {
        show(total, Some("total"));
    }
    if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
