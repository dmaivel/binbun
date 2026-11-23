//! Decoder throughput: binbun against iced-x86, Zydis, Capstone, XED and
//! others on x86-64; against exarmo, bad64, disarm64, fARM64, yaxpeax-arm,
//! Capstone and LLVM on AArch64.
//!
//! ```sh
//! cargo run --release -- [--out DIR] [FILE...]
//! cargo run --release -- --only zydis FILE...      # one contender, e.g. for perf
//! cargo run --release -- --task decode FILE...      # one task
//! cargo run --release -- --passes 20 --only binbun --task decode FILE...
//!     # exactly 20 untimed passes, for `perf stat` (prints instructions/pass)
//! cargo run --release -- --only binbun --task decode --samples 5 FILE...
//!     # quick check: 5 samples instead of 20 (no confidence interval
//!     # below 6)
//! XED_DIR=/path/to/xed cargo run --release -- ...   # also measure XED
//! CAPSTONE6_DIR=/path/to/capstone cargo run --release -- ...
//!     # also measure Capstone 6 on AArch64
//! ```
//!
//! The architecture is that of the given ELF or PE files, which must all
//! agree: x86-64 or AArch64 (by default this benchmark's own binary). Every
//! contender for it linearly sweeps their executable sections, skipping one
//! byte (x86-64) or one 4-byte word (AArch64) where it cannot decode. Each
//! task is timed separately; the result is the median throughput of
//! [`SAMPLES`] samples (or `--samples`), with a 95% confidence interval for
//! the median when there are at least [`MIN_INTERVAL_SAMPLES`].
//! Samples are taken in rounds, one per contender per round, so that slow
//! drift (temperature, other load) spreads over all contenders instead of
//! penalising whichever ran during it. Results go to stdout and, as raw
//! numbers, to `decode.json` (x86-64) or `decode-aarch64.json` in `--out`
//! (default `results/`); `plot.py` makes the Markdown report and charts from
//! them.

mod contenders;
mod corpus;
mod report;

use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use contenders::Contender;
use corpus::Corpus;
use serde::Serialize;

/// The instruction set of the corpus, and so of the contenders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    pub fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86-64",
            Self::Aarch64 => "AArch64",
        }
    }

    /// The tasks measured, in order.
    pub fn tasks(self) -> &'static [Task] {
        match self {
            Self::X86_64 => &[Task::Length, Task::Flow, Task::Decode, Task::Format],
            Self::Aarch64 => &[Task::Valid, Task::Decode, Task::Format],
        }
    }

    /// The file the raw results go to.
    pub fn results_file(self) -> &'static str {
        match self {
            Self::X86_64 => "decode.json",
            Self::Aarch64 => "decode-aarch64.json",
        }
    }
}

/// What a contender is asked to do per instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// Find the instruction's length only (x86-64).
    Length,
    /// Tell whether the word is an instruction (AArch64, where every
    /// instruction is 4 bytes long).
    Valid,
    /// What control-flow recovery needs (x86-64): the length, how the
    /// instruction transfers control, and a direct target.
    Flow,
    /// Decode the instruction fully: operation and operands.
    Decode,
    /// Decode it and format it as text (Intel syntax on x86-64).
    Format,
}

impl Task {
    pub fn name(self) -> &'static str {
        match self {
            Self::Length => "length",
            Self::Valid => "valid",
            Self::Flow => "flow",
            Self::Decode => "decode",
            Self::Format => "decode + format",
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Length => "length",
            Self::Valid => "valid",
            Self::Flow => "flow",
            Self::Decode => "decode",
            Self::Format => "format",
        }
    }
}

/// The outcome of one sweep over a buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Sweep {
    /// Instructions decoded.
    pub instructions: u64,
    /// Bytes (x86-64) or 4-byte words (AArch64) skipped because they did not
    /// decode.
    pub invalid: u64,
}

impl std::ops::AddAssign for Sweep {
    fn add_assign(&mut self, other: Self) {
        self.instructions += other.instructions;
        self.invalid += other.invalid;
    }
}

/// One contender's result for one task.
#[derive(Debug, Clone, Serialize)]
pub struct Measurement {
    pub contender: &'static str,
    pub detail: &'static str,
    pub sweep: Sweep,
    /// Bytes per second: the median, and the 95% confidence interval for
    /// the median.
    pub bytes_per_second: Estimate,
    /// Instructions per second, likewise.
    pub instructions_per_second: Estimate,
}

/// A median with a confidence interval, when there are enough samples for
/// one.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Estimate {
    pub median: f64,
    pub low: Option<f64>,
    pub high: Option<f64>,
}

impl Estimate {
    /// The median of `samples` and its 95% confidence interval, from order
    /// statistics (no assumption on the distribution of the noise).
    fn of(samples: &mut [f64]) -> Self {
        samples.sort_by(f64::total_cmp);
        let n = samples.len();
        let interval = median_interval(n);
        Self {
            median: if n % 2 == 1 {
                samples[n / 2]
            } else {
                f64::midpoint(samples[n / 2 - 1], samples[n / 2])
            },
            low: interval.map(|(low, _)| samples[low]),
            high: interval.map(|(_, high)| samples[high]),
        }
    }

    fn scaled(self, factor: f64) -> Self {
        Self {
            median: self.median * factor,
            low: self.low.map(|low| low * factor),
            high: self.high.map(|high| high * factor),
        }
    }
}

/// Indices (into `n` sorted samples) of the bounds of a confidence interval
/// of at least 95% for the median: the `k`-th smallest and largest samples,
/// `k` the largest with P(Binomial(n, 1/2) < k) ≤ 2.5%. `None` below
/// [`MIN_INTERVAL_SAMPLES`], where even the smallest and largest samples
/// bound the median with less than 95% confidence.
fn median_interval(n: usize) -> Option<(usize, usize)> {
    let mut below = 0.0; // P(X < k)
    let mut k = 0;
    let mut term = 0.5f64.powi(i32::try_from(n).unwrap_or(i32::MAX)); // P(X = 0)
    while k < n / 2 {
        if below + term > 0.025 {
            break;
        }
        below += term;
        k += 1;
        term *= (n - k + 1) as f64 / k as f64;
    }
    // P(X < k) ≤ 2.5% with k ≥ 1 means the k-th smallest (index k - 1).
    (k >= 1).then(|| (k - 1, n - k))
}

/// Timed samples per contender and task, unless `--samples` says otherwise.
const SAMPLES: usize = 20;
/// The fewest samples with a 95% confidence interval for the median.
pub const MIN_INTERVAL_SAMPLES: usize = 6;
const SAMPLE_TIME: Duration = Duration::from_millis(150);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = PathBuf::from("results");
    let mut only: Option<String> = None;
    let mut task_filter: Option<String> = None;
    let mut passes: Option<u32> = None;
    let mut samples = SAMPLES;
    let mut files = Vec::new();
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--out" {
            out = args.next().ok_or("--out needs a directory")?.into();
        } else if arg == "--only" {
            let name = args.next().ok_or("--only needs a decoder name")?;
            only = Some(name.to_string_lossy().to_lowercase());
        } else if arg == "--task" {
            let name = args
                .next()
                .ok_or("--task needs length or flow (x86-64), valid (AArch64), decode or format")?;
            task_filter = Some(name.to_string_lossy().into_owned());
        } else if arg == "--passes" {
            let n = args.next().ok_or("--passes needs a number")?;
            passes = Some(n.to_string_lossy().parse()?);
        } else if arg == "--samples" {
            let n = args.next().ok_or("--samples needs a number")?;
            samples = n.to_string_lossy().parse()?;
            if samples == 0 {
                return Err("--samples needs at least 1".into());
            }
        } else {
            files.push(PathBuf::from(arg));
        }
    }
    if files.is_empty() {
        files.push(std::env::current_exe()?);
    }

    let corpus = Corpus::load(&files)?;
    let arch = corpus.arch;
    if let Some(filter) = &task_filter
        && !arch.tasks().iter().any(|task| task.slug() == filter)
    {
        return Err(format!("{} has no task {filter}", arch.name()).into());
    }
    eprintln!(
        "corpus: {} bytes of {} code in {} sections",
        corpus.bytes(),
        arch.name(),
        corpus.sections.len()
    );
    let mut contenders = contenders::all(arch);
    if let Some(only) = &only {
        contenders.retain(|contender| contender.name().to_lowercase().starts_with(only.as_str()));
    }

    let mut results = Vec::new();
    for &task in arch.tasks() {
        if task_filter.as_deref().is_some_and(|t| t != task.slug()) {
            continue;
        }
        if let Some(passes) = passes {
            for contender in &mut contenders {
                if contender.supports(task).is_some() {
                    let mut sweep = Sweep::default();
                    for _ in 0..passes {
                        for section in &corpus.sections {
                            sweep +=
                                contender.sweep(task, black_box(&section.bytes), section.address);
                        }
                    }
                    println!(
                        "{} / {}: {} instructions decoded",
                        task.name(),
                        contender.name(),
                        sweep.instructions
                    );
                }
            }
            continue;
        }
        eprintln!("{}", task.name());
        let mut measurements = measure(&mut contenders, task, &corpus, samples);
        measurements.sort_by(|a, b| {
            b.bytes_per_second
                .median
                .total_cmp(&a.bytes_per_second.median)
        });
        results.push((task, measurements));
    }

    print!("{}", report::table(arch, samples, &results));
    report::write(&out, &corpus, samples, &results)?;
    eprintln!(
        "wrote {} (render with plot.py)",
        out.join(arch.results_file()).display()
    );
    Ok(())
}

/// Times every contender that supports `task`, `samples` times, one sample
/// of each per round.
fn measure(
    contenders: &mut [Box<dyn Contender>],
    task: Task,
    corpus: &Corpus,
    samples: usize,
) -> Vec<Measurement> {
    /// A contender being timed: its description, counts and sample rates.
    struct Run<'c> {
        contender: &'c mut Box<dyn Contender>,
        detail: &'static str,
        sweep: Sweep,
        rates: Vec<f64>,
    }
    let pass = |contender: &mut dyn Contender| {
        let mut sweep = Sweep::default();
        for section in &corpus.sections {
            sweep += contender.sweep(task, black_box(&section.bytes), section.address);
        }
        sweep
    };
    // One untimed pass each: the counts, and a warm-up.
    let mut runs: Vec<Run<'_>> = contenders
        .iter_mut()
        .filter_map(|contender| {
            let detail = contender.supports(task)?;
            let sweep = pass(contender.as_mut());
            Some(Run {
                contender,
                detail,
                sweep,
                rates: Vec::with_capacity(samples),
            })
        })
        .collect();
    for _ in 0..samples {
        for run in &mut runs {
            let start = Instant::now();
            let mut passes = 0u32;
            while start.elapsed() < SAMPLE_TIME {
                black_box(pass(run.contender.as_mut()));
                passes += 1;
            }
            run.rates
                .push(f64::from(passes) / start.elapsed().as_secs_f64());
        }
    }
    runs.into_iter()
        .map(|mut run| {
            let passes_per_second = Estimate::of(&mut run.rates);
            Measurement {
                contender: run.contender.name(),
                detail: run.detail,
                sweep: run.sweep,
                bytes_per_second: passes_per_second.scaled(corpus.bytes() as f64),
                instructions_per_second: passes_per_second.scaled(run.sweep.instructions as f64),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{MIN_INTERVAL_SAMPLES, SAMPLES, median_interval};

    #[test]
    fn interval_needs_enough_samples() {
        for n in 1..MIN_INTERVAL_SAMPLES {
            assert_eq!(median_interval(n), None, "{n} samples");
        }
        assert_eq!(median_interval(MIN_INTERVAL_SAMPLES), Some((0, 5)));
        // The 6th smallest and largest of 20.
        assert_eq!(median_interval(SAMPLES), Some((5, 14)));
    }
}
