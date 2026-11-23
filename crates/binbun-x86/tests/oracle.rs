//! Differential tests against Intel XED itself (`tools/xed-oracle`).
//!
//! ```sh
//! scripts/xed-oracle.sh /path/to/built/xed     # writes target/xed-oracle
//! BINBUN_XED_ORACLE=target/xed-oracle cargo test -p binbun-x86 --test oracle -- --ignored
//! ```
//!
//! `BINBUN_ORACLE_CASES` sets how many random inputs to try (default
//! 200 000) and `BINBUN_ORACLE_SEED` the seed. `real_code_matches_xed`
//! sweeps the files in `BINBUN_ORACLE_CORPUS` (`:`-separated; default
//! libc) as 64-bit code.
//!
//! A sample of XED's answers is checked in (`tests/data/xed-answers.txt`,
//! oracle output lines) so the comparison also runs without XED;
//! `BINBUN_WRITE_FIXTURE=1` with `lengths_match_xed` rewrites it.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

mod support;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

use binbun_x86::{Decoder, Instruction, MAX_LENGTH, Mode, decode};
use support::notation::{self, cpuid, decoded, flags, length, mode_tag, parse_mode};
use support::{MODES, Rng, address, hex, instruction};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/xed-answers.txt");
const FIXTURE_CASES: u64 = 10_000;
const FIXTURE_SEED: u64 = 0x5eed;

/// One input to the oracle.
struct Input {
    mode: Mode,
    address: u64,
    bytes: Vec<u8>,
}

/// One oracle line: the input and XED's answer.
struct Answer {
    input: Input,
    /// The whole answer, after the echoed input.
    whole: String,
    /// The length decoder's answer: the length or the error.
    length: String,
    /// `LENGTH ICLASS IFORM | OPERAND...`, or the error.
    decoded: String,
    /// XED's Intel-syntax text at the input's address; empty when decoding
    /// fails.
    text: String,
    /// XED's flags information (`READ:WRITTEN:UNDEFINED:MAY:MUST:ACTIONS`,
    /// `-` for none); empty when decoding fails.
    flags: String,
    /// The CPUID requirements of the instruction's isa set; empty when
    /// decoding fails.
    cpuid: String,
}

impl Input {
    /// `MODE ADDRESS HEX`, as the oracle reads and echoes it.
    fn show(&self) -> String {
        format!(
            "{} {:x} {}",
            mode_tag(self.mode),
            self.address,
            hex(&self.bytes)
        )
    }
}

impl Answer {
    /// Parses an oracle output line.
    fn parse(line: &str) -> Self {
        let mut columns = line.split('\t');
        let head = columns.next().unwrap();
        let mut next = || columns.next().unwrap_or_default().to_owned();
        let (text, flags, cpuid) = (next(), next(), next());
        let words: Vec<&str> = head.split_whitespace().collect();
        let whole = line.splitn(4, ' ').nth(3).unwrap().to_owned();
        let digits = words[2];
        let bytes = (0..digits.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).unwrap())
            .collect();
        // Successful decodes continue with the length; errors are one word
        // followed by `- - |`.
        let decoded = if words[4].parse::<usize>().is_ok() {
            words[4..].join(" ")
        } else {
            words[4].to_owned()
        };
        Self {
            input: Input {
                mode: parse_mode(words[0]).unwrap(),
                address: u64::from_str_radix(words[1], 16).unwrap(),
                bytes,
            },
            whole,
            length: words[3].to_owned(),
            decoded,
            text,
            flags,
            cpuid,
        }
    }
}

fn env_number(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The oracle's output lines for `inputs`.
fn ask_lines(inputs: &[Input]) -> String {
    let oracle =
        std::env::var("BINBUN_XED_ORACLE").expect("BINBUN_XED_ORACLE names the oracle binary");
    let mut child = Command::new(oracle)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the oracle runs");
    let mut stdin = child.stdin.take().unwrap();
    let text = inputs.iter().fold(String::new(), |mut text, input| {
        writeln!(text, "{}", input.show()).unwrap();
        text
    });
    let writer = std::thread::spawn(move || stdin.write_all(text.as_bytes()).unwrap());
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(output.status.success(), "the oracle failed");
    String::from_utf8(output.stdout).unwrap()
}

/// Asks the oracle about every input.
fn ask(inputs: &[Input]) -> Vec<Answer> {
    let answers: Vec<Answer> = ask_lines(inputs).lines().map(Answer::parse).collect();
    assert_eq!(
        answers.len(),
        inputs.len(),
        "the oracle answered every input"
    );
    answers
}

fn random_inputs(cases: u64, seed: u64) -> Vec<Input> {
    let mut rng = Rng::new(seed);
    (0..cases)
        .map(|_| {
            let mode = rng.pick(&MODES);
            Input {
                mode,
                address: address(&mut rng),
                bytes: instruction(&mut rng, mode),
            }
        })
        .collect()
}

/// Mismatches grouped by kind, with a count and a few examples each.
#[derive(Default)]
struct Mismatches(BTreeMap<String, (usize, Vec<String>)>);

impl Mismatches {
    fn add(&mut self, kind: String, example: impl FnOnce() -> String) {
        let entry = self.0.entry(kind).or_default();
        entry.0 += 1;
        if entry.1.len() < 4 {
            entry.1.push(example());
        }
    }

    /// Fails with the most frequent kinds of mismatch.
    fn assert_none(self, what: &str, compared: usize) {
        let mut by_count: Vec<_> = self.0.iter().collect();
        by_count.sort_by_key(|(_, (n, _))| std::cmp::Reverse(*n));
        let report =
            by_count
                .iter()
                .take(40)
                .fold(String::new(), |mut report, (kind, (n, examples))| {
                    writeln!(report, "{n:7} {kind}:").unwrap();
                    for example in examples {
                        writeln!(report, "          {example}").unwrap();
                    }
                    report
                });
        let total: usize = self.0.values().map(|(n, _)| n).sum();
        assert!(
            self.0.is_empty(),
            "{total} {what} of {compared} differ ({} kinds):\n{report}",
            self.0.len()
        );
    }
}

/// Lengths from the length decoder.
fn compare_lengths(answers: &[Answer]) {
    let mut mismatches = Mismatches::default();
    for answer in answers {
        let input = &answer.input;
        let ours = length(&input.bytes, input.mode);
        if ours != answer.length {
            mismatches.add(format!("xed {} / binbun {ours}", answer.length), || {
                input.show()
            });
        }
    }
    mismatches.assert_none("lengths", answers.len());
}

/// Full decodes: length, iclass, iform and operands, or the error.
fn compare_decoded(answers: &[Answer]) {
    let kind = |s: &str| {
        if s.starts_with(|c: char| c.is_ascii_digit()) {
            "ok".to_owned()
        } else {
            s.split_whitespace().next().unwrap_or("").to_owned()
        }
    };
    // For two decodes, the first part that differs: the instruction, or
    // an operand by name.
    let difference = |xed: &str, ours: &str| {
        let (xed_head, xed_operands) = xed.split_once(" |").unwrap_or((xed, ""));
        let (our_head, our_operands) = ours.split_once(" |").unwrap_or((ours, ""));
        if xed_head != our_head {
            return "instruction".to_owned();
        }
        let (x, o): (Vec<&str>, Vec<&str>) = (
            xed_operands.split_whitespace().collect(),
            our_operands.split_whitespace().collect(),
        );
        if x.len() != o.len() {
            return "operand count".to_owned();
        }
        x.iter()
            .zip(&o)
            .find(|(a, b)| a != b)
            .map_or_else(String::new, |(a, _)| {
                format!("operand {}", a.split(['=', ':']).next().unwrap_or(""))
            })
    };
    let mut mismatches = Mismatches::default();
    for answer in answers {
        let input = &answer.input;
        let ours = decoded(&decode(&input.bytes, input.mode));
        if ours != answer.decoded {
            let (xed_kind, our_kind) = (kind(&answer.decoded), kind(&ours));
            let key = if xed_kind == "ok" && our_kind == "ok" {
                difference(&answer.decoded, &ours)
            } else {
                format!("xed {xed_kind} / binbun {our_kind}")
            };
            mismatches.add(key, || {
                format!("{} [xed {} | binbun {ours}]", input.show(), answer.decoded)
            });
        }
    }
    mismatches.assert_none("decodes", answers.len());
}

/// XED's text, flags and CPUID columns of every input both decode.
fn compare_columns(answers: &[Answer]) {
    type Column = (
        &'static str,
        fn(&Answer) -> &str,
        fn(&Instruction, u64) -> String,
    );
    let columns: [Column; 3] = [
        ("text", |a| &a.text, |i, at| i.intel(at).to_string()),
        ("flags", |a| &a.flags, |i, _| flags(i)),
        ("cpuid", |a| &a.cpuid, |i, _| cpuid(i)),
    ];
    let mut mismatches = Mismatches::default();
    let mut compared = 0;
    for answer in answers {
        let input = &answer.input;
        let Ok(instruction) = decode(&input.bytes, input.mode) else {
            continue;
        };
        if answer.text.is_empty() {
            continue;
        }
        compared += 1;
        for (column, xed, binbun) in &columns {
            let (xed, ours) = (xed(answer), binbun(&instruction, input.address));
            if ours != xed {
                let kind = format!("{column} {}", instruction.mnemonic().as_str());
                mismatches.add(kind, || {
                    format!("{} [xed `{xed}` | binbun `{ours}`]", input.show())
                });
            }
        }
    }
    mismatches.assert_none("columns", compared);
}

fn compare(answers: &[Answer]) {
    compare_lengths(answers);
    compare_decoded(answers);
    compare_columns(answers);
    // The parts agree; so must the whole line the fuzz targets compare.
    for answer in answers {
        let input = &answer.input;
        assert_eq!(
            notation::answer(input.mode, input.address, &input.bytes),
            answer.whole,
            "{}",
            input.show()
        );
    }
}

#[test]
#[ignore = "needs BINBUN_XED_ORACLE; see the module documentation"]
fn lengths_match_xed() {
    let cases = env_number("BINBUN_ORACLE_CASES", 200_000);
    let answers = ask(&random_inputs(cases, env_number("BINBUN_ORACLE_SEED", 1)));
    compare_lengths(&answers);

    if std::env::var_os("BINBUN_WRITE_FIXTURE").is_some() {
        let lines = ask_lines(&random_inputs(FIXTURE_CASES, FIXTURE_SEED));
        std::fs::write(FIXTURE, lines).unwrap();
    }
}

#[test]
#[ignore = "needs BINBUN_XED_ORACLE; see the module documentation"]
fn decodes_match_xed() {
    let cases = env_number("BINBUN_ORACLE_CASES", 200_000);
    let answers = ask(&random_inputs(cases, env_number("BINBUN_ORACLE_SEED", 1)));
    compare_decoded(&answers);
    compare_columns(&answers);
}

/// Real code: a linear sweep over whole files (code and data alike) as
/// 64-bit code at the files' offsets plus a base address, each step
/// checked against XED, in batches to bound memory.
#[test]
#[ignore = "needs BINBUN_XED_ORACLE; see the module documentation"]
fn real_code_matches_xed() {
    const BASE: u64 = 0x7f00_0000_0000;
    const BATCH: usize = 500_000;
    let corpus =
        std::env::var("BINBUN_ORACLE_CORPUS").unwrap_or_else(|_| "/usr/lib/libc.so.6".to_owned());
    for path in corpus.split(':') {
        let file = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let mut decoder = Decoder::new(&file, Mode::Bits64, BASE);
        let mut total = 0;
        loop {
            let inputs: Vec<Input> = decoder
                .by_ref()
                .take(BATCH)
                .map(|(address, _)| {
                    let offset = usize::try_from(address - BASE).unwrap();
                    let end = (offset + MAX_LENGTH).min(file.len());
                    Input {
                        mode: Mode::Bits64,
                        address,
                        bytes: file[offset..end].to_vec(),
                    }
                })
                .collect();
            if inputs.is_empty() {
                break;
            }
            total += inputs.len();
            compare(&ask(&inputs));
        }
        println!("{path}: {total} instructions match");
    }
}

/// The checked-in sample of XED's answers.
#[test]
fn matches_recorded_xed_answers() {
    let text = std::fs::read_to_string(FIXTURE).expect("tests/data/xed-answers.txt exists");
    let answers: Vec<Answer> = text.lines().map(Answer::parse).collect();
    assert_eq!(answers.len(), usize::try_from(FIXTURE_CASES).unwrap());
    compare(&answers);
}
