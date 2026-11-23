//! Does the program behave the same with a function replaced by a tool's
//! recompiled C? DecompileBench's runtime test on this corpus: the
//! function is replaced in the running program (its entry patched to jump
//! to the C, loaded beside it; [`LOADER`]) and the program's own tests run
//! with it, their output compared with the original's.
//!
//! - The workload: bash's test suite (`tests/run-*`, each run as
//!   `run-all` runs it, with its output to standard output), each in a
//!   sandbox (bubblewrap: the file system read-only but for a private
//!   `/tmp` and a private overlay of the tests' directory), with the
//!   program under test as `THIS_SH`: Debian's bash for bash's functions;
//!   the same bash on the corpus' glibc for libc's. A test is kept if three
//!   runs of the original agree (output and exit status).
//! - The sample: functions the debug file states, at least 13 bytes long
//!   (the patch), that a kept test reaches (found by a breakpoint on every
//!   entry, removed when hit); a seeded random sample of `--sample` of them
//!   per file.
//! - Each tool's C for each sampled function is compiled in the first
//!   setting that compiles ([`crate::compile::Compiled::chosen`]), with
//!   `-fno-plt` (every reference to another name through the global offset
//!   table) into a shared object, its names of the program's functions and
//!   data (the tool's own names: binbun's address comments, the name lists
//!   Hex-Rays, Ghidra and angr give) bound to the original's, so the C works
//!   on the program's own state; names a tool neither declares nor the
//!   program or its libraries define trap if called.
//! - It behaves the same if every kept test reaching the function (up to
//!   the 10 quickest) gives the original's output and exit status, and it
//!   was reached. A tool without C for the function, or C that compiles in
//!   no setting, fails.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use binbun_bench::write_json;
use binbun_loader::Image;
use object::Object as _;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::compile::{self, Compiled, Headers};
use crate::cparse::{self, Pick};
use crate::tools::{Decompilation, Places, Text};
use crate::{Arguments, corpus, headers, parallel, truth, update_report};

/// The loader preloaded into every test's processes.
const LOADER: &str = "substitute.c";

/// Tests left out: `run-all` and those it leaves out, and `run-jobs`,
/// which waits for a terminal the sandbox has not.
const LEFT_OUT: [&str; 4] = ["run-all", "run-minimal", "run-gprof", "run-jobs"];

/// The most tests run per function.
const TESTS_PER_FUNCTION: usize = 10;

/// The patch's length: shorter functions are not sampled.
const PATCH: u64 = 13;

/// What runs the tests on one file's code.
struct Workload {
    /// The tests' directory.
    tests: PathBuf,
    /// The bash the tests run (`THIS_SH`).
    shell: PathBuf,
    /// The build ID of the module whose functions are replaced.
    build_id: String,
    /// The loader.
    loader: PathBuf,
}

/// One run of one test.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Outcome {
    /// Exit status (`None`: killed or timed out).
    status: Option<i32>,
    /// Standard output and error, together.
    output: Vec<u8>,
}

impl Workload {
    /// Runs `test` with `environment` (and `writable` directories), within
    /// `timeout`: its outcome and time.
    fn run(
        &self,
        test: &str,
        environment: &[(String, String)],
        writable: &[&Path],
        timeout: Duration,
    ) -> (Outcome, Duration) {
        let tests = self.tests.display().to_string();
        let mut command = Command::new("bwrap");
        command.args(["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]);
        command.args([
            "--tmpfs",
            "/tmp",
            "--overlay-src",
            &tests,
            "--tmp-overlay",
            &tests,
        ]);
        for dir in writable {
            command.arg("--bind").arg(dir).arg(dir);
        }
        command.args([
            "--chdir",
            &tests,
            "--unshare-pid",
            "--die-with-parent",
            "--new-session",
        ]);
        command.args(["env", "-i"]);
        command.arg(format!("PATH={tests}:/usr/bin:/bin"));
        command.args([
            "HOME=/tmp",
            "TERM=dumb",
            "TMPDIR=/tmp",
            "BASH_TSTOUT=/tmp/bashtst",
        ]);
        command.arg(format!("THIS_SH={}", self.shell.display()));
        command.arg(format!("LD_PRELOAD={}", self.loader.display()));
        command.arg(format!("BENCH_BUILD_ID={}", self.build_id));
        for (name, value) in environment {
            command.arg(format!("{name}={value}"));
        }
        command.args(["sh", &format!("./{test}")]);
        let (mut reader, writer) = match std::io::pipe() {
            Ok(pipe) => pipe,
            Err(_) => {
                return (
                    Outcome {
                        status: None,
                        output: b"no pipe".to_vec(),
                    },
                    Duration::ZERO,
                );
            }
        };
        let Ok(writer_err) = writer.try_clone() else {
            return (
                Outcome {
                    status: None,
                    output: b"no pipe".to_vec(),
                },
                Duration::ZERO,
            );
        };
        let started = Instant::now();
        let child = command
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(writer_err)
            .process_group(0)
            .spawn();
        drop(command);
        let mut child = match child {
            Ok(child) => child,
            Err(error) => {
                return (
                    Outcome {
                        status: None,
                        output: error.to_string().into_bytes(),
                    },
                    Duration::ZERO,
                );
            }
        };
        let id = child.id();
        let reading = std::thread::spawn(move || {
            let mut output = Vec::new();
            let _ = reader.read_to_end(&mut output);
            output
        });
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.code(),
                Ok(None) if started.elapsed() > timeout => {
                    let _ = Command::new("kill")
                        .args(["-KILL", "--", &format!("-{id}")])
                        .status();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break None,
            }
        };
        let elapsed = started.elapsed();
        let output = reading.join().unwrap_or_default();
        (
            Outcome {
                status: if timed_out { None } else { status },
                output,
            },
            elapsed,
        )
    }
}

/// The tests of a workload's directory.
fn tests(dir: &Path) -> Result<Vec<String>, String> {
    let mut found: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.starts_with("run-") && !LEFT_OUT.contains(&name.as_str()))
        .filter(|name| !name.ends_with(".orig") && !name.ends_with('~'))
        .collect();
    found.sort();
    Ok(found)
}

/// The original's runs of the kept tests.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Baseline {
    /// Each kept test's outcome and its slowest run's seconds.
    kept: BTreeMap<String, (Outcome, f64)>,
    /// Tests whose three runs differed.
    unstable: Vec<String>,
}

fn baseline(workload: &Workload, work: &Path, threads: usize) -> Result<Baseline, String> {
    let cached = work.join("baseline.json");
    if let Ok(text) = std::fs::read_to_string(&cached)
        && let Ok(baseline) = serde_json::from_str(&text)
    {
        return Ok(baseline);
    }
    let tests = tests(&workload.tests)?;
    println!("baseline: {} tests, three runs each", tests.len());
    let runs = parallel(&tests, threads, |test| {
        (0..3)
            .map(|_| workload.run(test, &[], &[], Duration::from_secs(120)))
            .collect::<Vec<_>>()
    });
    let mut baseline = Baseline {
        kept: BTreeMap::new(),
        unstable: Vec::new(),
    };
    for (test, runs) in tests.into_iter().zip(runs) {
        let first = &runs[0].0;
        if first.status.is_some() && runs.iter().all(|(outcome, _)| outcome == first) {
            let slowest = runs
                .iter()
                .map(|(_, t)| t.as_secs_f64())
                .fold(0.0, f64::max);
            baseline.kept.insert(test, (first.clone(), slowest));
        } else {
            baseline.unstable.push(test);
        }
    }
    write_json(&cached, &baseline).map_err(|e| e.to_string())?;
    Ok(baseline)
}

/// Which of `entries` each kept test reaches.
fn coverage(
    workload: &Workload,
    baseline: &Baseline,
    entries: &[u64],
    work: &Path,
    threads: usize,
) -> Result<BTreeMap<String, Vec<u64>>, String> {
    let cached = work.join("coverage.json");
    if let Ok(text) = std::fs::read_to_string(&cached)
        && let Ok(coverage) = serde_json::from_str(&text)
    {
        return Ok(coverage);
    }
    let dir = work.join("coverage");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let list = dir.join("entries");
    let text: String = entries.iter().map(|e| format!("{e:x}\n")).collect();
    std::fs::write(&list, text).map_err(|e| e.to_string())?;
    let tests: Vec<&String> = baseline.kept.keys().collect();
    println!("coverage: {} tests", tests.len());
    let reached = parallel(&tests, threads, |test| {
        let bitmap = dir.join(format!("{test}.bitmap"));
        if std::fs::write(&bitmap, vec![0u8; entries.len()]).is_err() {
            return Vec::new();
        }
        let environment = [
            ("BENCH_COVERAGE".to_owned(), bitmap.display().to_string()),
            ("BENCH_ENTRIES".to_owned(), list.display().to_string()),
        ];
        let timeout = Duration::from_secs_f64((baseline.kept[*test].1 * 5.0).max(30.0));
        workload.run(test, &environment, &[&dir], timeout);
        let bits = std::fs::read(&bitmap).unwrap_or_default();
        let _ = std::fs::remove_file(&bitmap);
        entries
            .iter()
            .zip(bits)
            .filter(|&(_, bit)| bit != 0)
            .map(|(&entry, _)| entry)
            .collect::<Vec<u64>>()
    });
    let coverage: BTreeMap<String, Vec<u64>> = tests.into_iter().cloned().zip(reached).collect();
    write_json(&cached, &coverage).map_err(|e| e.to_string())?;
    Ok(coverage)
}

/// A seeded shuffle (xorshift64*), the same on every machine.
fn shuffle<T>(items: &mut [T], seed: u64) {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    for i in (1..items.len()).rev() {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let value = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        let j = usize::try_from(value % (i as u64 + 1)).unwrap_or(0);
        items.swap(i, j);
    }
}

/// What became of one tool's C for one function.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Verdict {
    /// `same`, `differs`, `not-reached`, `not-decompiled`, `not-compiled`,
    /// `not-linked`.
    status: String,
    /// Tests run.
    tests: usize,
    /// The first test that differed, and how.
    note: Option<String>,
}

/// The address a tool's `name` stands for in the file, if the tool says.
fn address_of(
    name: &str,
    tool: &str,
    text: &Text,
    decompilation: &Decompilation,
    mapped: &dyn Fn(u64) -> bool,
) -> Option<u64> {
    let found = if tool.starts_with("binbun") {
        // binbun's declarations end with the address: `/* 0x4000 */`.
        let Text::C { own, .. } = text else {
            return None;
        };
        own.lines().find_map(|line| {
            let (declaration, comment) = line.rsplit_once("/* 0x")?;
            let address = u64::from_str_radix(comment.strip_suffix(" */")?, 16).ok()?;
            let named = declaration
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|word| word == name);
            named.then_some(address)
        })
    } else {
        decompilation.names.get(name).copied().or_else(|| {
            // The tools' names made of an address.
            let (prefix, hex) = name.rsplit_once('_')?;
            let value = u64::from_str_radix(hex, 16).ok()?;
            match (tool, prefix) {
                ("ghidra", "FUN" | "DAT" | "LAB" | "PTR" | "_DAT") => value.checked_sub(0x10_0000),
                ("angr", "g" | "sub") => value.checked_sub(0x40_0000),
                (
                    "hexrays",
                    "sub" | "byte" | "word" | "dword" | "qword" | "xmmword" | "off" | "unk"
                    | "stru" | "asc" | "loc" | "jpt" | "flt" | "dbl",
                ) => Some(value),
                _ => None,
            }
        })
    }?;
    mapped(found).then_some(found)
}

/// Builds `tool`'s C for `function` into a shared object in `dir` with
/// its name map: the object, the function's name in it, the map.
#[allow(clippy::too_many_arguments)]
fn build(
    tool: &str,
    text: &Text,
    chosen: &(compile::Setting, Vec<String>),
    decompilation: &Decompilation,
    headers: &Headers,
    mapped: &dyn Fn(u64) -> bool,
    dir: &Path,
) -> Result<(PathBuf, String, PathBuf), String> {
    let (source, includes) =
        compile::source(tool, chosen.0, text, headers).ok_or("no source in that setting")?;
    let object = dir.join("f.o");
    let mut flags = chosen.1.clone();
    flags.extend(["-fno-plt".to_owned(), "-w".to_owned()]);
    compile::compile("clang", &source, &includes, &flags, Some(&object))
        .map_err(|e| format!("compile: {}", compile::category(&e)))?;
    let Text::C { function, .. } = text else {
        return Err("no C".to_owned());
    };
    let pick = if tool.starts_with("binbun") {
        Pick::Last
    } else {
        Pick::First
    };
    let name = cparse::facts(function, pick)
        .map(|f| f.name)
        .filter(|n| !n.is_empty())
        .ok_or("no function definition")?;
    // The object's names: undefined, and defined globally.
    let listing = Command::new("nm")
        .arg("-P")
        .arg(&object)
        .output()
        .map_err(|e| format!("nm: {e}"))?;
    let listing = String::from_utf8_lossy(&listing.stdout);
    let mut undefined = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut defines_function = false;
    for line in listing.lines() {
        let mut fields = line.split_whitespace();
        let (Some(symbol), Some(kind)) = (fields.next(), fields.next()) else {
            continue;
        };
        if kind == "U" {
            undefined.insert(symbol.to_owned());
            names.insert(symbol.to_owned());
        } else if kind.chars().all(|c| c.is_ascii_uppercase()) {
            names.insert(symbol.to_owned());
            defines_function |= symbol == name;
        }
    }
    if !defines_function {
        return Err(format!("{name} is not a global function of the C"));
    }
    let mut map = String::new();
    for symbol in &names {
        if let Some(address) = address_of(symbol, tool, text, decompilation, mapped) {
            map.push_str(&format!("{symbol} {address:x}\n"));
        }
    }
    let map_path = dir.join("map");
    std::fs::write(&map_path, map).map_err(|e| e.to_string())?;
    // Every undefined name defined as a trap: those the program and its
    // libraries define are bound to theirs first (the object is loaded
    // after them), those mapped are bound to the original's.
    let mut glue = String::from(".text\n");
    for symbol in &undefined {
        glue.push_str(&format!(
            ".globl {symbol}\n.type {symbol}, @function\n{symbol}:\n    ud2\n"
        ));
    }
    let glue_path = dir.join("glue.s");
    std::fs::write(&glue_path, glue).map_err(|e| e.to_string())?;
    let shared = dir.join("f.so");
    let output = Command::new("clang")
        .args(["-shared", "-o"])
        .arg(&shared)
        .arg(&object)
        .arg(&glue_path)
        .args(["-Wl,-z,norelro", "-Wl,-z,now", "-lm"])
        .output()
        .map_err(|e| format!("link: {e}"))?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr);
        return Err(format!("link: {}", message.lines().next().unwrap_or("")));
    }
    Ok((shared, name, map_path))
}

/// Wilson's 95% interval for `part` of `whole`.
fn wilson(part: usize, whole: usize) -> (f64, f64) {
    if whole == 0 {
        return (0.0, 1.0);
    }
    let (n, p, z) = (whole as f64, part as f64 / whole as f64, 1.96_f64);
    let centre = (p + z * z / (2.0 * n)) / (1.0 + z * z / n);
    let spread = z * (p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt() / (1.0 + z * z / n);
    ((centre - spread).max(0.0), (centre + spread).min(1.0))
}

pub fn run(arguments: &Arguments) -> Result<(), String> {
    let corpus_dir = arguments
        .corpus
        .as_deref()
        .ok_or("behaviour needs --corpus")?;
    let places = Places::from_environment(&arguments.work);
    let headers = headers(corpus_dir, &arguments.work, &places)?;
    // The loader, built once.
    let loader = arguments.work.join("substitute.so");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("decompile")
        .join(LOADER);
    let status = Command::new("gcc")
        .args(["-O2", "-shared", "-fPIC", "-o"])
        .arg(&loader)
        .arg(&source)
        .arg("-ldl")
        .status()
        .map_err(|e| format!("gcc: {e}"))?;
    if !status.success() {
        return Err("cannot build the loader".to_owned());
    }
    let loader = std::fs::canonicalize(&loader).map_err(|e| e.to_string())?;
    for file in corpus(corpus_dir, &arguments.files) {
        let work = std::fs::canonicalize(arguments.work.join(file.name))
            .map_err(|e| format!("{}: {e} (run quality first)", file.name))?;
        let behaviour_work = work.join("behaviour");
        std::fs::create_dir_all(&behaviour_work).map_err(|e| e.to_string())?;
        let data = std::fs::read(&file.binary).map_err(|e| e.to_string())?;
        let image = Image::parse(&data).map_err(|e| e.to_string())?;
        let build_id = object::File::parse(&*data)
            .ok()
            .and_then(|f| f.build_id().ok().flatten().map(<[u8]>::to_vec))
            .ok_or("no build ID")?;
        let workload = Workload {
            tests: corpus_dir
                .join("bash/tests")
                .canonicalize()
                .map_err(|e| e.to_string())?,
            shell: corpus_dir
                .join(if file.name == "libc" {
                    "libc/bash"
                } else {
                    "bash/bash"
                })
                .canonicalize()
                .map_err(|e| e.to_string())?,
            build_id: build_id.iter().map(|b| format!("{b:02x}")).collect(),
            loader: loader.clone(),
        };
        let (truth, _) = truth::functions(
            &image,
            &data,
            &file.debug,
            (file.source_prefix, &file.source),
        )?;
        let baseline = baseline(&workload, &behaviour_work, arguments.threads)?;
        println!(
            "{}: {} tests kept, {} unstable",
            file.name,
            baseline.kept.len(),
            baseline.unstable.len()
        );
        let candidates: Vec<u64> = truth
            .values()
            .filter(|f| f.size.is_some_and(|s| s >= PATCH))
            .map(|f| f.entry)
            .collect();
        let coverage = coverage(
            &workload,
            &baseline,
            &candidates,
            &behaviour_work,
            arguments.threads,
        )?;
        let mut reached_by: BTreeMap<u64, Vec<&String>> = BTreeMap::new();
        for (test, entries) in &coverage {
            for entry in entries {
                reached_by.entry(*entry).or_default().push(test);
            }
        }
        let mut sample: Vec<u64> = reached_by.keys().copied().collect();
        let reached = sample.len();
        shuffle(&mut sample, arguments.seed);
        sample.truncate(arguments.sample);
        sample.sort_unstable();
        println!(
            "{}: {reached} functions reached, {} sampled",
            file.name,
            sample.len()
        );

        let segments: Vec<(u64, u64)> = image
            .segments
            .iter()
            .map(|s| (s.start, s.start + s.size))
            .collect();
        let mapped = |address: u64| segments.iter().any(|&(s, e)| s <= address && address < e);
        let mut tool_results = Vec::new();
        for tool in &arguments.tools {
            let read = |name: String| -> Result<String, String> {
                std::fs::read_to_string(work.join(&name))
                    .map_err(|e| format!("{name}: {e} (run quality first)"))
            };
            let decompilation: Decompilation =
                serde_json::from_str(&read(format!("{tool}.json"))?).map_err(|e| e.to_string())?;
            let verdicts: BTreeMap<u64, Compiled> =
                serde_json::from_str(&read(format!("compiled-{tool}.json"))?)
                    .map_err(|e| e.to_string())?;
            let cached = behaviour_work.join(format!("{tool}.json"));
            let mut done: BTreeMap<u64, Verdict> = std::fs::read_to_string(&cached)
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or_default();
            let todo: Vec<u64> = sample
                .iter()
                .copied()
                .filter(|e| !done.contains_key(e))
                .collect();
            println!("{}: {tool}: {} functions to test", file.name, todo.len());
            let verdicts_now = parallel(&todo, arguments.threads, |&entry| {
                let Some(text @ Text::C { .. }) = decompilation.functions.get(&entry) else {
                    return Verdict {
                        status: "not-decompiled".to_owned(),
                        tests: 0,
                        note: None,
                    };
                };
                let Some(chosen) = verdicts.get(&entry).and_then(|v| v.chosen.clone()) else {
                    return Verdict {
                        status: "not-compiled".to_owned(),
                        tests: 0,
                        note: None,
                    };
                };
                let dir = behaviour_work
                    .join("jobs")
                    .join(format!("{tool}-{entry:x}"));
                let _ = std::fs::create_dir_all(&dir);
                let verdict =
                    match build(tool, text, &chosen, &decompilation, &headers, &mapped, &dir) {
                        Err(why) => Verdict {
                            status: "not-linked".to_owned(),
                            tests: 0,
                            note: Some(why),
                        },
                        Ok((shared, name, map)) => {
                            let mark = dir.join("reached");
                            let environment = [
                                ("BENCH_SO".to_owned(), shared.display().to_string()),
                                ("BENCH_FUNCTION".to_owned(), name),
                                ("BENCH_ENTRY".to_owned(), format!("{entry:x}")),
                                ("BENCH_MAP".to_owned(), map.display().to_string()),
                                ("BENCH_MARK".to_owned(), mark.display().to_string()),
                            ];
                            let mut tests: Vec<&String> = reached_by[&entry].clone();
                            tests.sort_by(|a, b| {
                                baseline.kept[*a]
                                    .1
                                    .total_cmp(&baseline.kept[*b].1)
                                    .then(a.cmp(b))
                            });
                            tests.truncate(TESTS_PER_FUNCTION);
                            let mut verdict = Verdict {
                                status: "same".to_owned(),
                                tests: 0,
                                note: None,
                            };
                            for test in tests {
                                let (expected, seconds) = &baseline.kept[test];
                                let timeout = Duration::from_secs_f64((seconds * 5.0).max(10.0));
                                let (outcome, _) =
                                    workload.run(test, &environment, &[&dir], timeout);
                                verdict.tests += 1;
                                if outcome != *expected {
                                    let how = match outcome.status {
                                        None => "killed or timed out".to_owned(),
                                        Some(status) if Some(status) != expected.status => {
                                            format!("exit status {status}")
                                        }
                                        Some(_) => "output".to_owned(),
                                    };
                                    verdict.status = "differs".to_owned();
                                    verdict.note = Some(format!("{test}: {how}"));
                                    break;
                                }
                            }
                            if verdict.status == "same" && !mark.exists() {
                                verdict.status = "not-reached".to_owned();
                            }
                            verdict
                        }
                    };
                let _ = std::fs::remove_dir_all(&dir);
                verdict
            });
            for (entry, verdict) in todo.into_iter().zip(verdicts_now) {
                done.insert(entry, verdict);
            }
            write_json(&cached, &done).map_err(|e| e.to_string())?;
            let mut statuses: BTreeMap<String, usize> = BTreeMap::new();
            for entry in &sample {
                *statuses.entry(done[entry].status.clone()).or_default() += 1;
            }
            let same = statuses.get("same").copied().unwrap_or(0);
            let (low, high) = wilson(same, sample.len());
            println!(
                "{}: {tool}: same {same}/{} ({:.1}%, 95% CI {:.1}–{:.1}%)",
                file.name,
                sample.len(),
                same as f64 * 100.0 / sample.len().max(1) as f64,
                low * 100.0,
                high * 100.0
            );
            tool_results.push(json!({
                "tool": tool,
                "same": same,
                "low": low,
                "high": high,
                "statuses": statuses,
            }));
        }
        let entry = json!({
            "name": file.name,
            "tests_kept": baseline.kept.len(),
            "tests_unstable": baseline.unstable,
            "reached": reached,
            "candidates": candidates.len(),
            "sampled": sample.len(),
            "seed": arguments.seed,
            "tools": tool_results,
        });
        let fields = json!({ "tests_per_function": TESTS_PER_FUNCTION });
        update_report(&arguments.out, "behaviour", fields, entry)?;
    }
    Ok(())
}
