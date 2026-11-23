//! Decompilation: binbun against Ghidra and angr (and, with `--private`,
//! Hex-Rays and Binary Ninja), on stripped copies of Debian's bash and
//! glibc's libc scored against their debug files and sources. The method
//! follows DecompileBench (Gao et al.,
//! Findings of ACL 2025): does each function's C compile, and does the
//! program still behave the same with the function replaced by its
//! recompiled C.
//!
//! ```sh
//! decompile/corpus.sh CORPUS                         # fetched once
//! cargo run --release --bin decompile -- quality --corpus CORPUS [--private] [--work DIR] [--out DIR]
//! cargo run --release --bin decompile -- behaviour --corpus CORPUS [--private] [--work DIR] [--out DIR]
//! cargo run --release --bin decompile -- speed [--private] [--timeout SECS] FILE...
//! python3 plot.py                                    # decompile.md and its chart
//! ```
//!
//! - `quality`: every tool decompiles each corpus file whole (stripped as
//!   the function recovery benchmark strips, symbols used only for
//!   scoring), timed with its startup; each function the debug file states
//!   is then compiled ([`compile`]) and its prototype, locals, gotos,
//!   nesting and lines compared with the debug file and the source
//!   ([`cparse`], [`truth`]).
//! - `behaviour`: a sample of the functions bash's own test suite runs,
//!   each replaced in the running program by each tool's recompiled C, the
//!   suite's output compared with the original's ([`behaviour`]).
//! - `speed`: the whole-file times alone, on other files (a PE).
//!
//! binbun is the `binbun` command at `BINBUN` (default `binbun` on the
//! path; `BINBUN_COMMIT` names the commit it was built from, for the
//! report). The others are found as `cfg` finds them: `GHIDRA_DIR`
//! (default `/opt/ghidra`), `ANGR_PYTHON`
//! (`~/.cache/binbun/angr-venv/bin/python`); Ghidra's projects go to
//! `GHIDRA_PROJECTS` (default `WORK/ghidra-projects`; Ghidra refuses a
//! path with an element starting with `.`). `--private` runs Hex-Rays too
//! (`IDA_DIR`, default `~/ida-pro-9.4`), and Binary Ninja where
//! `BINJA_MCP` is the URL of the MCP server a running one hosts (its free
//! edition has no other way in: `decompile/binja_mcp.py`); their licences
//! restrict publishing their results, so these go to `results/private/`,
//! which is not tracked. Results go to `decompile.json` in `--out`
//! (default `results/`), each command rewriting its own part; tool
//! outputs and verdicts are kept in `--work` (default
//! `results/decompile-work`) and reused.

mod behaviour;
mod compile;
mod cparse;
mod tools;
mod truth;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use binbun_bench::{cpu, write_json};
use binbun_loader::{Image, SymbolSource};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::compile::{Compiled, Headers};
use crate::cparse::{Facts, Pick};
use crate::tools::{Decompilation, Ended, Places, Text};

/// The function recovery benchmark's timeout, for whole-file times.
const TIMEOUT: Duration = Duration::from_secs(900);

/// One corpus file: its name, where it is in the corpus, its debug file,
/// and its source (the prefix the debug file's paths have, the directory
/// it is in).
pub struct CorpusFile {
    pub name: &'static str,
    pub binary: PathBuf,
    pub debug: PathBuf,
    pub source_prefix: &'static str,
    pub source: PathBuf,
}

/// The corpus `corpus.sh` fetched into `dir`, only the files named in
/// `only` if any are.
pub fn corpus(dir: &Path, only: &[PathBuf]) -> Vec<CorpusFile> {
    let files = vec![
        CorpusFile {
            name: "bash",
            binary: dir.join("bash/bash"),
            debug: dir.join("bash/bash.debug"),
            source_prefix: "",
            source: dir.join("bash/src"),
        },
        CorpusFile {
            name: "libc",
            binary: dir.join("libc/libc.so.6"),
            debug: dir.join("libc/libc.so.6.debug"),
            source_prefix: "/usr/src/debug/glibc/glibc",
            source: dir.join("libc/src"),
        },
    ];
    files
        .into_iter()
        .filter(|f| only.is_empty() || only.iter().any(|n| n.as_os_str() == f.name))
        .collect()
}

struct Arguments {
    corpus: Option<PathBuf>,
    work: PathBuf,
    out: PathBuf,
    tools: Vec<String>,
    files: Vec<PathBuf>,
    threads: usize,
    angr_shards: usize,
    sample: usize,
    seed: u64,
    timeout: Duration,
    /// Leave angr's whole-file timing out (for a run sharing the CPUs).
    no_timing: bool,
}

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let mut arguments = Arguments {
        corpus: None,
        work: PathBuf::from("results/decompile-work"),
        out: PathBuf::new(),
        tools: Vec::new(),
        files: Vec::new(),
        threads: 16,
        angr_shards: 8,
        sample: 500,
        seed: 1,
        timeout: TIMEOUT,
        no_timing: false,
    };
    let mut private = false;
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--corpus" => arguments.corpus = Some(value("--corpus")?.into()),
            "--work" => arguments.work = value("--work")?.into(),
            "--out" => arguments.out = value("--out")?.into(),
            "--tools" => {
                arguments.tools = value("--tools")?.split(',').map(str::to_owned).collect();
            }
            "--threads" => {
                arguments.threads = value("--threads")?.parse().map_err(|_| "bad --threads")?;
            }
            "--angr-shards" => {
                arguments.angr_shards = value("--angr-shards")?
                    .parse()
                    .map_err(|_| "bad --angr-shards")?;
            }
            "--sample" => {
                arguments.sample = value("--sample")?.parse().map_err(|_| "bad --sample")?;
            }
            "--seed" => arguments.seed = value("--seed")?.parse().map_err(|_| "bad --seed")?,
            "--timeout" => {
                let seconds = value("--timeout")?.parse().map_err(|_| "bad --timeout")?;
                arguments.timeout = Duration::from_secs(seconds);
            }
            "--no-timing" => arguments.no_timing = true,
            "--private" => private = true,
            _ => arguments.files.push(PathBuf::from(arg)),
        }
    }
    if arguments.tools.is_empty() {
        arguments.tools = tools::tools(private);
    }
    if arguments.out.as_os_str().is_empty() {
        arguments.out = PathBuf::from(if private { "results/private" } else { "results" });
    }
    std::fs::create_dir_all(&arguments.work).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&arguments.out).map_err(|e| e.to_string())?;
    match command.as_str() {
        "quality" => quality(&arguments),
        "behaviour" => behaviour::run(&arguments),
        "speed" => speed(&arguments),
        _ => Err(
            "usage: decompile quality|behaviour --corpus DIR [--private] [--work DIR] [--out DIR] [--tools LIST]\n       decompile speed [--private] [--timeout SECS] FILE..."
                .to_owned(),
        ),
    }
}

/// Sets `key` of `decompile.json` in `out` to `fields` with `file` in its
/// `files` (replacing the one of the same name), keeping the rest: of a
/// file and of the section's object fields (`versions`), what a run of
/// some tools (`--tools`) did not give, its other tools' results.
fn update_report(out: &Path, key: &str, fields: Value, file: Value) -> Result<(), String> {
    let path = out.join("decompile.json");
    let mut report: Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| json!({}));
    report["cpu"] = json!(cpu());
    report["timeout_seconds"] = json!(TIMEOUT.as_secs());
    let mut files = report[key]["files"].as_array().cloned().unwrap_or_default();
    match files.iter_mut().find(|f| f["name"] == file["name"]) {
        Some(old) => *old = merge_tools(old, file),
        None => files.push(file),
    }
    let mut section = fields;
    if let (Some(new), Some(old)) = (section.as_object_mut(), report[key].as_object()) {
        for (name, value) in new.iter_mut() {
            if let (Some(fresh), Some(kept)) = (
                value.as_object_mut(),
                old.get(name).and_then(Value::as_object),
            ) {
                for (field, earlier) in kept {
                    fresh
                        .entry(field.clone())
                        .or_insert_with(|| earlier.clone());
                }
            }
        }
    }
    section["files"] = Value::Array(files);
    report[key] = section;
    write_json(&path, &report).map_err(|e| format!("{}: {e}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}

/// The fields of a tool's `source` compared on the functions every tool
/// decompiled (`common`).
const STRUCTURE: [&str; 9] = [
    "common",
    "locals_ratio_median",
    "locals_same",
    "locals_more",
    "locals_fewer",
    "lines_ratio_median",
    "gotos_mean",
    "functions_with_gotos",
    "nesting_mean",
];

/// `file` with the entries of its per-tool lists (`tools`, `speed`) it
/// lacks taken from `old`, in `old`'s order, the tools it has replacing
/// theirs. Where it keeps tools of `old`'s (a run of some tools), the
/// structure the run compared on its own tools' common functions is not
/// comparable with theirs: the file keeps `old`'s `source`, and the
/// run's tools have no structure figures (`common` 0, the others null).
fn merge_tools(old: &Value, mut file: Value) -> Value {
    let same = |a: &Value, b: &Value| a["tool"] == b["tool"];
    let subset = match (file["tools"].as_array(), old["tools"].as_array()) {
        (Some(fresh), Some(kept)) => kept
            .iter()
            .any(|earlier| !fresh.iter().any(|entry| same(entry, earlier))),
        _ => false,
    };
    if subset {
        file["source"] = old["source"].clone();
        for tool in file["tools"].as_array_mut().into_iter().flatten() {
            for field in STRUCTURE {
                tool["source"][field] = if field == "common" {
                    json!(0)
                } else {
                    Value::Null
                };
            }
        }
    }
    merge_lists(old, file)
}

/// `file` with the entries of its per-tool lists (`tools`, `speed`) it
/// lacks taken from `old`, in `old`'s order, the tools it has replacing
/// theirs.
fn merge_lists(old: &Value, mut file: Value) -> Value {
    for list in ["tools", "speed"] {
        let (Some(fresh), Some(kept)) = (file[list].as_array(), old[list].as_array()) else {
            continue;
        };
        let same = |a: &Value, b: &Value| a["tool"] == b["tool"];
        let mut merged: Vec<Value> = kept
            .iter()
            .map(|earlier| {
                fresh
                    .iter()
                    .find(|entry| same(entry, earlier))
                    .unwrap_or(earlier)
                    .clone()
            })
            .collect();
        merged.extend(
            fresh
                .iter()
                .filter(|entry| !kept.iter().any(|earlier| same(earlier, entry)))
                .cloned(),
        );
        file[list] = Value::Array(merged);
    }
    file
}

/// Runs `work` on each of `items` on `threads` threads.
pub fn parallel<T: Sync, R: Send>(
    items: &[T],
    threads: usize,
    work: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..threads.max(1) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(index) else {
                        break;
                    };
                    let result = work(item);
                    if let Ok(mut results) = results.lock() {
                        results[index] = Some(result);
                    }
                }
            });
        }
    });
    results
        .into_inner()
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.expect("every item is done"))
        .collect()
}

/// What the tools are given of `file`: for an ELF file a copy alone in a
/// directory of `work`, without symbol tables, without its
/// `.gnu_debuglink` and with its build ID zeroed ([`forget_build_id`]):
/// Ghidra and IDA load the debug file the link names, or one filed under
/// the build ID, and Binary Ninja one lying beside the file under its
/// name, which is the file the scores are made from. Else a copy without
/// symbol tables, or `file` itself if it has none (as `cfg` strips).
pub fn stripped(file: &Path, work: &Path) -> Result<PathBuf, String> {
    let data = std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let image = Image::parse(&data).map_err(|e| e.to_string())?;
    let elf = data.starts_with(b"\x7fELF");
    if !elf
        && !image
            .symbols
            .iter()
            .any(|s| s.source == SymbolSource::Static)
    {
        return Ok(file.to_owned());
    }
    let target = work
        .join("stripped")
        .join(file.file_name().ok_or("no file name")?);
    std::fs::create_dir_all(work.join("stripped")).map_err(|e| e.to_string())?;
    let mut strip = std::process::Command::new("strip");
    strip.arg("--strip-all");
    if elf {
        strip.arg("--remove-section=.gnu_debuglink");
    }
    let status = strip
        .arg("-o")
        .arg(&target)
        .arg(file)
        .status()
        .map_err(|e| format!("strip: {e}"))?;
    if !status.success() {
        return Err(format!("strip failed on {}", file.display()));
    }
    if elf {
        forget_build_id(&target)?;
    }
    Ok(target)
}

/// Zeroes the GNU build ID of the (little-endian) ELF file at `path`,
/// where it is: the descriptor of each note of name size 4, type 3
/// (`NT_GNU_BUILD_ID`) and name `GNU`. Nothing moves. Ghidra finds a
/// debug file by the ID in the debuginfod client's cache
/// (`~/.cache/debuginfod_client/ID/debuginfo`, which a debugger run on
/// the same file once leaves there), IDA under
/// `/usr/lib/debug/.build-id`.
fn forget_build_id(path: &Path) -> Result<(), String> {
    let mut data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut at = 0;
    while at + 16 <= data.len() {
        let size = u32::from_le_bytes([data[at + 4], data[at + 5], data[at + 6], data[at + 7]]);
        let end = at + 16 + size as usize;
        if data[at..at + 4] == [4, 0, 0, 0]
            && data[at + 8..at + 16] == *b"\x03\0\0\0GNU\0"
            && (1..=64).contains(&size)
            && end <= data.len()
        {
            data[at + 16..end].fill(0);
            at = end;
        } else {
            at += 4;
        }
    }
    std::fs::write(path, data).map_err(|e| format!("{}: {e}", path.display()))
}

/// A tool's whole-file time as the reports give it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Timing {
    pub tool: String,
    /// `ok`, `timeout` or `failed`.
    pub status: String,
    pub seconds: f64,
    pub note: Option<String>,
}

impl Timing {
    fn of(tool: &str, ended: &Ended) -> Self {
        let (status, seconds, note) = match ended {
            Ended::Done(time) if *time > TIMEOUT => (
                "timeout",
                time.as_secs_f64(),
                Some(format!("timed out after {} s", TIMEOUT.as_secs())),
            ),
            Ended::Done(time) => ("ok", time.as_secs_f64(), None),
            Ended::Timeout(time) => (
                "timeout",
                time.as_secs_f64(),
                Some(format!("timed out after {:.0} s", time.as_secs_f64())),
            ),
            Ended::Failed(time, why) => ("failed", time.as_secs_f64(), Some(why.clone())),
        };
        Self {
            tool: tool.to_owned(),
            status: status.to_owned(),
            seconds,
            note,
        }
    }
}

/// `tool`'s decompilation of `file`, from `work` if a run left it there.
fn decompilation(
    tool: &str,
    file: &Path,
    work: &Path,
    arguments: &Arguments,
    places: &Places,
) -> Result<Decompilation, String> {
    let cached = work.join(format!("{tool}.json"));
    if let Ok(text) = std::fs::read_to_string(&cached)
        && let Ok(decompilation) = serde_json::from_str(&text)
    {
        return Ok(decompilation);
    }
    println!("{}: running {tool}", file.display());
    let decompilation = match tool {
        "binbun" | "binbun-reading" => tools::binbun(
            file,
            tool == "binbun-reading",
            places,
            work,
            Duration::from_secs(4 * 3600),
        )?,
        // A generous limit: the outputs are wanted whatever the time; the
        // speed table says what took over 900 s.
        "hexrays" => tools::hexrays(file, places, work, Duration::from_secs(4 * 3600))?,
        "ghidra" => tools::ghidra(file, places, work, Duration::from_secs(4 * 3600))?,
        "angr" => tools::angr(file, places, work, arguments.angr_shards, 300)?,
        "binja" => tools::binja(file, places, work, Duration::from_secs(4 * 3600))?,
        other => return Err(format!("unknown tool {other}")),
    };
    write_json(&cached, &decompilation).map_err(|e| e.to_string())?;
    Ok(decompilation)
}

/// Every tool's verdicts on every function of the truth, from `work` if a
/// run left them there.
fn verdicts(
    decompilation: &Decompilation,
    truth: &BTreeMap<u64, truth::Function>,
    headers: &Headers,
    work: &Path,
    threads: usize,
) -> Result<BTreeMap<u64, Compiled>, String> {
    let cached = work.join(format!("compiled-{}.json", decompilation.tool));
    if let Ok(text) = std::fs::read_to_string(&cached)
        && let Ok(verdicts) = serde_json::from_str(&text)
    {
        return Ok(verdicts);
    }
    println!("compiling {}'s C", decompilation.tool);
    let entries: Vec<u64> = truth
        .keys()
        .copied()
        .filter(|entry| decompilation.functions.contains_key(entry))
        .collect();
    let results = parallel(&entries, threads, |entry| {
        compile::verdicts(
            &decompilation.tool,
            &decompilation.functions[entry],
            headers,
        )
    });
    let verdicts: BTreeMap<u64, Compiled> = entries.into_iter().zip(results).collect();
    write_json(&cached, &verdicts).map_err(|e| e.to_string())?;
    Ok(verdicts)
}

/// Where `binbun_defs.h` is written, for the files including it.
fn binbun_header(work: &Path) -> Result<PathBuf, String> {
    let dir = work.join("binbun-include");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("binbun_defs.h"), binbun_print::c::HEADER)
        .map_err(|e| e.to_string())?;
    Ok(dir)
}

pub fn headers(corpus: &Path, work: &Path, places: &Places) -> Result<Headers, String> {
    Ok(Headers {
        binbun: binbun_header(work)?,
        ida: places.ida.join("include"),
        decompilebench: corpus.join("decompilebench"),
    })
}

fn version_of(command: &str) -> String {
    std::process::Command::new(command)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|t| t.lines().next().map(str::to_owned))
        .unwrap_or_else(|| format!("{command}: not found"))
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    Some(if values.len() % 2 == 0 {
        f64::midpoint(values[middle - 1], values[middle])
    } else {
        values[middle]
    })
}

fn mean(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

fn quality(arguments: &Arguments) -> Result<(), String> {
    let corpus_dir = arguments
        .corpus
        .as_deref()
        .ok_or("quality needs --corpus")?;
    let places = Places::from_environment(&arguments.work);
    let headers = headers(corpus_dir, &arguments.work, &places)?;
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    for file in corpus(corpus_dir, &arguments.files) {
        let work = arguments.work.join(file.name);
        std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
        let data =
            std::fs::read(&file.binary).map_err(|e| format!("{}: {e}", file.binary.display()))?;
        let image = Image::parse(&data).map_err(|e| e.to_string())?;
        let (truth, excluded_assembly) = truth::functions(
            &image,
            &data,
            &file.debug,
            (file.source_prefix, &file.source),
        )?;
        let input = stripped(&file.binary, &work)?;
        println!("{}: {} functions stated", file.name, truth.len());

        // The source's facts, by function.
        let mut sources: BTreeMap<PathBuf, BTreeMap<String, Facts>> = BTreeMap::new();
        for function in truth.values() {
            if let Some(path) = &function.source
                && !sources.contains_key(path)
            {
                let text = std::fs::read(path).map_err(|e| e.to_string())?;
                let text = String::from_utf8_lossy(&text);
                sources.insert(path.clone(), cparse::all_facts(&text));
            }
        }
        let source_facts: BTreeMap<u64, &Facts> = truth
            .values()
            .filter(|f| !f.clone_of_source())
            .filter_map(|f| {
                let facts = sources.get(f.source.as_ref()?)?.get(&f.name)?;
                Some((f.entry, facts))
            })
            .collect();

        let mut timings = Vec::new();
        let mut per_tool = Vec::new();
        for tool in &arguments.tools {
            let decompilation = decompilation(tool, &input, &work, arguments, &places)?;
            versions.insert(
                if tool.starts_with("binbun") {
                    "binbun".to_owned()
                } else {
                    tool.clone()
                },
                decompilation.version.clone(),
            );
            if let Some(seconds) = decompilation.seconds {
                timings.push(Timing::of(
                    tool,
                    &Ended::Done(Duration::from_secs_f64(seconds)),
                ));
            } else {
                let cached = work.join(format!("{tool}-timed.json"));
                let timing = match std::fs::read_to_string(&cached)
                    .ok()
                    .and_then(|t| serde_json::from_str(&t).ok())
                {
                    Some(timing) => timing,
                    None if arguments.no_timing => Timing {
                        tool: tool.clone(),
                        status: "failed".to_owned(),
                        seconds: 0.0,
                        note: Some("not timed".to_owned()),
                    },
                    None => {
                        println!("{}: timing {tool} whole", file.name);
                        let timing =
                            Timing::of(tool, &tools::timed(tool, &input, &places, &work, TIMEOUT));
                        write_json(&cached, &timing).map_err(|e| e.to_string())?;
                        timing
                    }
                };
                timings.push(timing);
            }
            let verdicts = verdicts(&decompilation, &truth, &headers, &work, arguments.threads)?;
            let facts: BTreeMap<u64, Facts> = truth
                .keys()
                .filter_map(|entry| match decompilation.functions.get(entry)? {
                    Text::C { function, .. } => {
                        let pick = if tool.starts_with("binbun") {
                            Pick::Last
                        } else {
                            Pick::First
                        };
                        Some((*entry, cparse::facts(function, pick)?))
                    }
                    Text::Failed(_) => None,
                })
                .collect();
            per_tool.push((tool.clone(), decompilation, verdicts, facts));
        }

        // Structure is compared on the functions every tool decompiled and
        // whose source was found.
        let common: Vec<u64> = source_facts
            .keys()
            .copied()
            .filter(|entry| {
                per_tool
                    .iter()
                    .all(|(_, _, _, facts)| facts.contains_key(entry))
            })
            .collect();
        let signature: Vec<&truth::Function> =
            truth.values().filter(|f| !f.clone_of_source()).collect();
        let parameters_total: usize = signature.iter().map(|f| f.parameters.len()).sum();

        let mut tool_results = Vec::new();
        for (tool, decompilation, verdicts, facts) in &per_tool {
            let count = |check: &dyn Fn(&Compiled) -> bool| {
                truth
                    .keys()
                    .filter(|entry| verdicts.get(entry).is_some_and(check))
                    .count()
            };
            let decompiled = truth
                .keys()
                .filter(|entry| matches!(decompilation.functions.get(entry), Some(Text::C { .. })))
                .count();
            let mut errors: BTreeMap<String, usize> = BTreeMap::new();
            for entry in truth.keys() {
                match (decompilation.functions.get(entry), verdicts.get(entry)) {
                    (None, _) => *errors.entry("no such function".to_owned()).or_default() += 1,
                    (Some(Text::Failed(_)), _) => {
                        *errors.entry("not decompiled".to_owned()).or_default() += 1;
                    }
                    (Some(Text::C { .. }), Some(verdict)) if !verdict.own_clang => {
                        let category = verdict.error.clone().unwrap_or_else(|| "failed".to_owned());
                        *errors.entry(category).or_default() += 1;
                    }
                    _ => {}
                }
            }
            let mut errors: Vec<(String, usize)> = errors.into_iter().collect();
            errors.sort_by_key(|(category, count)| (std::cmp::Reverse(*count), category.clone()));
            errors.truncate(8);
            let decompilebench_applies = verdicts.values().any(|v| v.decompilebench.is_some());

            // The source's prototypes.
            let (mut count_right, mut returns_exact, mut returns_width) = (0, 0, 0);
            let (mut count_more, mut count_fewer) = (0, 0);
            let (mut parameters_exact, mut parameters_width) = (0, 0);
            for function in &signature {
                let Some(facts) = facts.get(&function.entry) else {
                    continue;
                };
                match facts.parameters.len().cmp(&function.parameters.len()) {
                    std::cmp::Ordering::Equal => count_right += 1,
                    std::cmp::Ordering::Greater => count_more += 1,
                    std::cmp::Ordering::Less => count_fewer += 1,
                }
                if facts.returns.exact(&function.returns) {
                    returns_exact += 1;
                }
                if facts.returns.width(&function.returns) {
                    returns_width += 1;
                }
                for (index, truth) in function.parameters.iter().enumerate() {
                    if let Some(ty) = facts.parameters.get(index) {
                        if ty.exact(truth) {
                            parameters_exact += 1;
                        }
                        if ty.width(truth) {
                            parameters_width += 1;
                        }
                    }
                }
            }
            let locals: Vec<f64> = common
                .iter()
                .filter(|entry| truth[entry].locals > 0)
                .map(|entry| facts[entry].locals as f64 / truth[entry].locals as f64)
                .collect();
            let locals_compared = |order: std::cmp::Ordering| {
                common
                    .iter()
                    .filter(|entry| facts[*entry].locals.cmp(&truth[*entry].locals) == order)
                    .count()
            };
            let lines: Vec<f64> = common
                .iter()
                .map(|entry| facts[entry].lines as f64 / source_facts[entry].lines.max(1) as f64)
                .collect();
            let gotos: Vec<f64> = common.iter().map(|e| facts[e].gotos as f64).collect();
            let nesting: Vec<f64> = common.iter().map(|e| facts[e].nesting as f64).collect();
            let functions_with_gotos = common.iter().filter(|e| facts[*e].gotos > 0).count();
            tool_results.push(json!({
                "tool": tool,
                "version": decompilation.version,
                "decompiled": decompiled,
                "recompile": {
                    "own_clang": count(&|v| v.own_clang),
                    "own_c23": count(&|v| v.own_c23),
                    "own_strict": count(&|v| v.own_clang || v.own_c23),
                    "own_gcc": count(&|v| v.own_gcc),
                    "own_lenient": count(&|v| v.own_lenient),
                    "libc_lenient": count(&|v| v.libc_lenient),
                    "decompilebench": decompilebench_applies.then(|| count(&|v| v.decompilebench == Some(true))),
                    "any": count(&Compiled::any),
                },
                "errors": errors,
                "source": {
                    "functions": signature.len(),
                    "parameters": parameters_total,
                    "parameter_count": count_right,
                    "parameter_count_more": count_more,
                    "parameter_count_fewer": count_fewer,
                    "returns_exact": returns_exact,
                    "returns_width": returns_width,
                    "parameters_exact": parameters_exact,
                    "parameters_width": parameters_width,
                    "common": common.len(),
                    "locals_ratio_median": median(locals),
                    "locals_same": locals_compared(std::cmp::Ordering::Equal),
                    "locals_more": locals_compared(std::cmp::Ordering::Greater),
                    "locals_fewer": locals_compared(std::cmp::Ordering::Less),
                    "lines_ratio_median": median(lines),
                    "gotos_mean": mean(&gotos),
                    "functions_with_gotos": functions_with_gotos,
                    "nesting_mean": mean(&nesting),
                },
            }));
        }
        let source_gotos: Vec<f64> = common
            .iter()
            .map(|e| source_facts[e].gotos as f64)
            .collect();
        let source_nesting: Vec<f64> = common
            .iter()
            .map(|e| source_facts[e].nesting as f64)
            .collect();
        let source_lines: Vec<f64> = common
            .iter()
            .map(|e| source_facts[e].lines as f64)
            .collect();
        let source_locals: Vec<f64> = common.iter().map(|e| truth[e].locals as f64).collect();
        let entry = json!({
            "name": file.name,
            "path": file.binary.display().to_string(),
            "stripped": input != file.binary,
            "functions": truth.len(),
            "signature_functions": signature.len(),
            "excluded_assembly": excluded_assembly,
            "clones": truth.len() - signature.len(),
            "with_source": source_facts.len(),
            "source": {
                "common": common.len(),
                "gotos_mean": mean(&source_gotos),
                "functions_with_gotos": common.iter().filter(|e| source_facts[*e].gotos > 0).count(),
                "nesting_mean": mean(&source_nesting),
                "lines_mean": mean(&source_lines),
                "locals_mean": mean(&source_locals),
            },
            "tools": tool_results,
            "speed": timings,
        });
        let fields = json!({
            "versions": versions,
            "compilers": { "clang": version_of("clang"), "gcc": version_of("gcc") },
            "flags": compile::FLAGS,
            "binbun": places.binbun.display().to_string(),
            // The commit the `binbun` command was built from, as the caller
            // states it (the command does not say).
            "binbun_commit": std::env::var("BINBUN_COMMIT").ok(),
        });
        update_report(&arguments.out, "quality", fields, entry)?;
    }
    Ok(())
}

/// Whole-file times of every tool on `files` (no scoring).
fn speed(arguments: &Arguments) -> Result<(), String> {
    let places = Places::from_environment(&arguments.work);
    for file in &arguments.files {
        let name = file
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let work = arguments.work.join(format!("speed-{name}"));
        std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
        let input = stripped(file, &work)?;
        let mut timings = Vec::new();
        for tool in &arguments.tools {
            let ended = tools::timed(tool, &input, &places, &work, arguments.timeout);
            let timing = Timing::of(tool, &ended);
            println!("{name}: {tool}: {} {:.2} s", timing.status, timing.seconds);
            timings.push(timing);
        }
        let entry = json!({
            "name": name,
            "path": file.display().to_string(),
            "speed": timings,
        });
        update_report(&arguments.out, "speed", json!({}), entry)?;
    }
    Ok(())
}
