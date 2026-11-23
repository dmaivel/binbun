//! isla-check: binbun's AArch64 L0 (`binbun_aarch64_lift`) against
//! sail-arm, word by word.
//!
//! ```sh
//! cd tools/isla-check && cargo build --release
//! target/release/isla-check --sweep                    # every family
//! target/release/isla-check 0xf1001420 0x54000040      # given words
//! ```
//!
//! - `--ir FILE`: the Jib snapshot `armv9p4.ir` (default `$BINBUN_ISLA_IR`,
//!   else `~/.cache/binbun-isla/armv9p4.ir`, where `scripts/isla-snapshot.sh`
//!   puts it).
//! - `--pc ADDRESS`: where the instruction is (repeatable; PC-relative
//!   forms are checked at every one given; default three addresses that
//!   exercise branch-target top-byte-ignore and wrapping).
//! - `--jobs N`: words checked at once (default 8).
//! - `--timeout SECONDS`: isla's limit per word (default 300).
//! - `--sweep`: every word of [`isla_check::sweep::FAMILIES`].
//! - `--family TEXT` (repeatable): the words of the families whose name
//!   contains TEXT.
//!
//! Prints every word that is not proved equivalent (with its
//! counterexample) and a summary per encoding; exits with 1 if any was not.

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use binbun_aarch64::decode;
use binbun_aarch64_lift::{AARCH64, LiftError, lift};
use isla_check::sweep::{FAMILIES, words};
use isla_check::{Model, Verdict, check, with_model};

/// Default addresses: a user address, one whose forward branches cross
/// into bit 55 and 56, and one whose backward branches wrap below 0.
const PCS: [u64; 3] = [
    0x0000_7fff_1234_5670,
    0x007f_ffff_ffff_fff8,
    0x0000_0000_0000_1000,
];

struct Arguments {
    ir: String,
    pcs: Vec<u64>,
    jobs: usize,
    timeout: u64,
    sweep: bool,
    /// `--family TEXT`: only the families whose name contains one of them.
    families: Vec<String>,
    words: Vec<u32>,
}

fn number(text: &str) -> Result<u64, String> {
    let parsed = match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(&hex.replace('_', ""), 16),
        None => text.replace('_', "").parse(),
    };
    parsed.map_err(|error| format!("{text}: {error}"))
}

fn arguments() -> Result<Arguments, String> {
    let mut arguments = Arguments {
        ir: std::env::var("BINBUN_ISLA_IR").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            format!("{home}/.cache/binbun-isla/armv9p4.ir")
        }),
        pcs: Vec::new(),
        jobs: 8,
        timeout: 300,
        sweep: false,
        families: Vec::new(),
        words: Vec::new(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--ir" => arguments.ir = value()?,
            "--pc" => arguments.pcs.push(number(&value()?)?),
            "--jobs" => {
                arguments.jobs = usize::try_from(number(&value()?)?).map_err(|e| e.to_string())?;
            }
            "--timeout" => arguments.timeout = number(&value()?)?,
            "--sweep" => arguments.sweep = true,
            "--family" => arguments.families.push(value()?),
            word => {
                let word = u32::try_from(number(word)?).map_err(|e| format!("{word}: {e}"))?;
                arguments.words.push(word);
            }
        }
    }
    if arguments.pcs.is_empty() {
        arguments.pcs = PCS.to_vec();
    }
    if !arguments.sweep && arguments.families.is_empty() && arguments.words.is_empty() {
        return Err("usage: isla-check [--ir FILE] [--pc ADDRESS]… [--jobs N] [--timeout SECONDS] (--sweep | --family TEXT… | WORD…)".into());
    }
    Ok(arguments)
}

/// One word at one address.
struct Case {
    word: u32,
    pc: u64,
}

fn cases(arguments: &Arguments) -> Vec<Case> {
    let mut cases = Vec::new();
    let mut add = |word: u32, pc_relative: bool| {
        let pcs = if pc_relative {
            arguments.pcs.as_slice()
        } else {
            arguments.pcs.get(..1).unwrap_or_default()
        };
        cases.extend(pcs.iter().map(|&pc| Case { word, pc }));
    };
    if arguments.sweep || !arguments.families.is_empty() {
        let chosen = |name: &str| {
            arguments.families.is_empty()
                || arguments
                    .families
                    .iter()
                    .any(|text| name.contains(text.as_str()))
        };
        for family in FAMILIES.iter().filter(|family| chosen(family.name)) {
            for word in words(family) {
                add(word, family.pc_relative);
            }
        }
    }
    for &word in &arguments.words {
        add(word, true);
    }
    cases
}

/// What happened to one case.
enum Outcome {
    /// Not an instruction with semantics (why).
    Skipped(String),
    /// Checked.
    Checked {
        encoding: &'static str,
        text: String,
        verdict: Verdict,
    },
}

fn run_case(model: &Model<'_>, case: &Case) -> Outcome {
    let instruction = match decode(case.word) {
        Ok(instruction) => instruction,
        Err(error) => return Outcome::Skipped(format!("{error:?}")),
    };
    let encoding = instruction.encoding().name();
    let text = instruction.display(case.pc).to_string();
    let verdict = match lift(&instruction, case.pc) {
        Ok(semantics) => check(model, case.word, case.pc, &semantics, &AARCH64),
        Err(LiftError::Unsupported) => {
            return Outcome::Skipped(format!("{encoding}: no semantics"));
        }
        Err(LiftError::Problem(problem)) => Verdict::Unsupported(format!("lift: {problem}")),
    };
    Outcome::Checked {
        encoding,
        text,
        verdict,
    }
}

/// Per encoding: checked, equivalent, counterexamples, unsupported, paths.
type Tally = BTreeMap<&'static str, [usize; 5]>;

fn sweep(model: &Model<'_>, arguments: &Arguments) -> bool {
    let cases = cases(arguments);
    let next = AtomicUsize::new(0);
    let outcomes = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..arguments.jobs.max(1) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(case) = cases.get(index) else { break };
                    let outcome = run_case(model, case);
                    if let Ok(mut outcomes) = outcomes.lock() {
                        outcomes.push((index, outcome));
                        if outcomes.len() % 100 == 0 {
                            eprintln!("{} of {} words", outcomes.len(), cases.len());
                        }
                    }
                }
            });
        }
    });
    let mut outcomes = outcomes.into_inner().unwrap_or_default();
    outcomes.sort_by_key(|(index, _)| *index);
    let mut tally = Tally::new();
    let mut skipped = BTreeMap::<String, usize>::new();
    let mut all_equivalent = true;
    for (index, outcome) in &outcomes {
        let Some(case) = cases.get(*index) else {
            continue;
        };
        match outcome {
            Outcome::Skipped(why) => *skipped.entry(why.clone()).or_default() += 1,
            Outcome::Checked {
                encoding,
                text,
                verdict,
            } => {
                let counts = tally.entry(encoding).or_default();
                counts[0] += 1;
                match verdict {
                    Verdict::Equivalent { paths, .. } => {
                        counts[1] += 1;
                        counts[4] += paths;
                    }
                    Verdict::Counterexample(_) => counts[2] += 1,
                    Verdict::Unsupported(_) => counts[3] += 1,
                }
                if !matches!(verdict, Verdict::Equivalent { .. }) {
                    all_equivalent = false;
                    println!(
                        "{:#010x} {encoding} `{text}` at {:#x}: {verdict}",
                        case.word, case.pc
                    );
                }
            }
        }
    }
    println!("\nencoding                    words  equivalent  counterexample  unsupported  paths");
    for (encoding, [words, equivalent, counterexamples, unsupported, paths]) in &tally {
        println!(
            "{encoding:<27} {words:>5}  {equivalent:>10}  {counterexamples:>14}  {unsupported:>11}  {paths:>5}"
        );
    }
    let total = tally.values().fold([0; 5], |mut sum, counts| {
        for (s, c) in sum.iter_mut().zip(counts) {
            *s += c;
        }
        sum
    });
    println!(
        "{:<27} {:>5}  {:>10}  {:>14}  {:>11}  {:>5}",
        "total", total[0], total[1], total[2], total[3], total[4]
    );
    for (why, count) in &skipped {
        println!("skipped {count}: {why}");
    }
    all_equivalent
}

fn main() -> ExitCode {
    let arguments = match arguments() {
        Ok(arguments) => arguments,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let ir = match std::fs::read_to_string(&arguments.ir) {
        Ok(ir) => ir,
        Err(error) => {
            eprintln!("{}: {error}", arguments.ir);
            return ExitCode::from(2);
        }
    };
    match with_model(&ir, 1, Some(arguments.timeout), |model| {
        sweep(model, &arguments)
    }) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
