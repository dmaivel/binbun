//! The signatures evaluation's second Rust program
//! (scripts/signatures/corpus.sh): the most frequent words of the files
//! named, counted on threads, using more of the standard library
//! (collections, strings, formatting, threads, channels, sorting, paths).

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

fn words(text: &str) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for word in text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
    {
        *counts.entry(word.to_lowercase()).or_insert(0) += 1;
    }
    counts
}

fn main() {
    let mut args = env::args().skip(1);
    let top: usize = args.next().and_then(|n| n.parse().ok()).unwrap_or(10);
    let files: Vec<PathBuf> = args.map(PathBuf::from).collect();
    let (sender, receiver) = mpsc::channel();
    let handles: Vec<_> = files
        .into_iter()
        .map(|file| {
            let sender = sender.clone();
            thread::spawn(move || {
                let counted = fs::read_to_string(&file).map(|text| words(&text));
                let _ = sender.send((file, counted));
            })
        })
        .collect();
    drop(sender);
    let mut total: HashMap<String, usize> = HashMap::new();
    let mut failed = BTreeMap::new();
    for (file, counted) in receiver {
        match counted {
            Ok(counts) => {
                for (word, n) in counts {
                    *total.entry(word).or_insert(0) += n;
                }
            }
            Err(error) => {
                failed.insert(file.display().to_string(), error.to_string());
            }
        }
    }
    for handle in handles {
        let _ = handle.join();
    }
    let mut ranked: Vec<(String, usize)> = total.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (word, n) in ranked.iter().take(top) {
        println!("{n:>8} {word}");
    }
    for (file, error) in &failed {
        eprintln!("freq: {file}: {error}");
    }
    if !failed.is_empty() {
        std::process::exit(1);
    }
}
