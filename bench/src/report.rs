//! The text table, and the raw results for `plot.py`.

use std::fmt::Write as _;
use std::path::Path;

use binbun_bench::{cpu, write_json};
use serde::Serialize;

use crate::corpus::Corpus;
use crate::{Arch, Estimate, MIN_INTERVAL_SAMPLES, Measurement, Task};

const MB: f64 = 1_000_000.0;

/// The 95% confidence interval in MB, or a dash without one.
fn interval(estimate: Estimate) -> String {
    match (estimate.low, estimate.high) {
        (Some(low), Some(high)) => format!("{:.0}–{:.0}", low / MB, high / MB),
        _ => "—".to_owned(),
    }
}

/// Markdown tables, one per task, from `samples` samples each.
pub fn table(arch: Arch, samples: usize, results: &[(Task, Vec<Measurement>)]) -> String {
    let skipped = match arch {
        Arch::X86_64 => "Skipped bytes",
        Arch::Aarch64 => "Invalid words",
    };
    let mut out = String::new();
    if samples < MIN_INTERVAL_SAMPLES {
        let _ = writeln!(
            out,
            "\n{samples} samples: no 95% confidence interval (that needs {MIN_INTERVAL_SAMPLES})."
        );
    }
    for (task, measurements) in results {
        let _ = writeln!(out, "\n### {}\n", task.name());
        let _ = writeln!(
            out,
            "| Decoder | MB/s | 95% CI | M instructions/s | Instructions | {skipped} | How |"
        );
        let _ = writeln!(out, "|---|---:|---:|---:|---:|---:|---|");
        for m in measurements {
            let _ = writeln!(
                out,
                "| {} | {:.0} | {} | {:.1} | {} | {} | {} |",
                m.contender,
                m.bytes_per_second.median / MB,
                interval(m.bytes_per_second),
                m.instructions_per_second.median / MB,
                m.sweep.instructions,
                m.sweep.invalid,
                m.detail
            );
        }
    }
    out
}

/// The whole run, as `decode.json` or `decode-aarch64.json`.
#[derive(Serialize)]
struct Report<'a> {
    cpu: String,
    /// Timed samples per contender and task.
    samples: usize,
    corpus: Vec<CorpusFile>,
    tasks: Vec<TaskResults<'a>>,
}

#[derive(Serialize)]
struct CorpusFile {
    path: String,
    /// Bytes of code swept.
    bytes: usize,
}

#[derive(Serialize)]
struct TaskResults<'a> {
    name: &'static str,
    slug: &'static str,
    measurements: &'a [Measurement],
}

/// Writes the architecture's results file, from `samples` samples per
/// measurement, into `dir`.
pub fn write(
    dir: &Path,
    corpus: &Corpus,
    samples: usize,
    results: &[(Task, Vec<Measurement>)],
) -> std::io::Result<()> {
    let report = Report {
        cpu: cpu(),
        samples,
        corpus: corpus
            .files
            .iter()
            .map(|(path, bytes)| CorpusFile {
                path: path.display().to_string(),
                bytes: *bytes,
            })
            .collect(),
        tasks: results
            .iter()
            .map(|(task, measurements)| TaskResults {
                name: task.name(),
                slug: task.slug(),
                measurements,
            })
            .collect(),
    };
    write_json(&dir.join(corpus.arch.results_file()), &report)
}
