//! Times opening a file as the GUI's session does, phase by phase, and
//! optionally writes every function's C in both views (one at a time,
//! the session's path) for comparing outputs before and after a change.
//!
//! `cargo run --release -p binbun --example speed -- FILE [GOLDEN_OUT]`;
//! with `--callers` for `GOLDEN_OUT`, it stops once the callers are found.

#![allow(clippy::unwrap_used, reason = "a command-line example fails loudly")]

use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::{Options, View};
use binbun_loader::Image;

fn resident_mib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .unwrap_or(0)
        / 1024
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap();
    let golden = args.next();
    let start = Instant::now();
    let lap = |what: &str, since: &mut Instant| {
        eprintln!(
            "{what:24} {:7.2} s  (at {:7.2} s, peak {} MiB)",
            since.elapsed().as_secs_f64(),
            start.elapsed().as_secs_f64(),
            resident_mib()
        );
        *since = Instant::now();
    };
    let mut since = Instant::now();
    let data = std::fs::read(&path).unwrap();
    let image = Image::parse(&data).unwrap();
    lap("parse", &mut since);
    let database = Database::new(&image, Seeds::ALL).unwrap();
    lap("find functions", &mut since);
    eprintln!("  {} functions", database.program().functions.len());
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let progress = database.progress();
        let done = &done;
        scope.spawn(move || {
            // Each pass, as the counter starts it again: its total, and
            // when it began.
            let mut last: Option<(usize, usize)> = None;
            let mut began = Instant::now();
            while !done.load(Ordering::Relaxed) {
                let now = progress.get();
                if let (Some((d, t)), Some((ld, lt))) = (now, last)
                    && (d < ld || t != lt)
                {
                    eprintln!(
                        "    pass of {lt:6}: {:6.2} s",
                        began.elapsed().as_secs_f64()
                    );
                    began = Instant::now();
                }
                if last.is_none() && now.is_some() {
                    began = Instant::now();
                }
                last = now;
                std::thread::sleep(Duration::from_millis(2));
            }
            if let Some((_, t)) = last {
                eprintln!(
                    "    pass of {t:6}: {:6.2} s (last)",
                    began.elapsed().as_secs_f64()
                );
            }
        });
        let _ = database.references();
        lap("references", &mut since);
        let _ = database.callers_both(&[]);
        lap("callers (both views)", &mut since);
        done.store(true, Ordering::Relaxed);
    });
    if golden.as_deref() == Some("--callers") {
        return;
    }
    let ids: Vec<_> = database.functions().map(|(id, _)| id).collect();
    let mut out = String::new();
    for view in [View::Reading, View::Exact] {
        let options = Options {
            style: Some("kr".to_owned()),
            view,
            ..Options::default()
        };
        let mut failed = 0;
        for &id in &ids {
            let output = database.decompile(id, &options);
            match &output.result {
                Ok(decompiled) => {
                    if golden.is_some() {
                        let c = decompiled.c.as_ref().map_or("", |c| c.text.as_str());
                        let _ = writeln!(out, "// {view:?} {:#x}\n{c}", output.entry);
                    }
                }
                Err(why) => {
                    failed += 1;
                    if golden.is_some() {
                        let _ = writeln!(out, "// {view:?} {:#x} failed: {why}", output.entry);
                    }
                }
            }
        }
        lap(&format!("decompile all ({view:?})"), &mut since);
        eprintln!("  {failed} failed");
    }
    if let Some(golden) = golden {
        std::fs::write(golden, out).unwrap();
    }
}
