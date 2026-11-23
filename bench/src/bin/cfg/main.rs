//! Function recovery: binbun against IDA, Ghidra, angr, radare2, rizin and
//! Falcon, on stripped binaries scored against what their unstripped
//! originals state.
//!
//! ```sh
//! cargo run --release --bin cfg -- [--tools binbun,ida,...] [--timeout SECS] [--out DIR] FILE...
//! python3 plot.py                     # cfg.md and charts from cfg.json
//! ```
//!
//! For each file, the reference is the function starts its original states
//! (symbols, unwind tables, PE exports), read with binutils (see
//! [`reference`]), in executable memory, outside PLT sections and other than
//! import thunks (`jmp [slot]` through an import slot), which tools count as
//! functions or not by taste and are left out on both sides. Each tool
//! then gets a copy stripped of symbol tables (`strip --strip-all`, which
//! keeps unwind tables and dynamic symbols, as stripped binaries in the
//! wild do; a file without a symbol table is used as is). Function starts
//! are compared after moving each tool's addresses to the file's own base.
//! Times are wall-clock, including each tool's startup.
//!
//! Tools are found at `IDA_DIR` (default `~/ida-pro-9.4`), `GHIDRA_DIR`
//! (`/opt/ghidra`), `ANGR_PYTHON` (`~/.cache/binbun/angr-venv/bin/python`),
//! `FALCON_FUNCTIONS` (`falcon/target/release/falcon-functions`, built with
//! `cargo build --release` in `falcon/`), and `r2`/`rizin` on `PATH`.
//! A missing tool is reported and skipped. Each runs in its own process
//! group, killed as a whole on timeout (Ghidra's launcher is a script).
//!
//! Each result is printed as it comes; the raw numbers go to `cfg.json` in
//! `--out` (default `results/`), rewritten after each file.

mod reference;

use std::collections::BTreeSet;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use binbun::analysis::{Seeds, analyse, type_library, x86_mode};
use binbun_bench::{cpu, write_json};
use binbun_loader::{Format, Image, SymbolSource};
use binbun_semantics::core::memory::Memory as _;
use binbun_x86::{Mnemonic, Register, Value, decode};
use serde::Serialize;

/// The tools compared, in report order.
const TOOLS: [&str; 7] = [
    "binbun", "ida", "ghidra", "angr", "radare2", "rizin", "falcon",
];

/// Sections whose code is import stubs, which tools count as functions or
/// not by taste: left out on both sides.
const STUB_SECTIONS: [&str; 3] = [".plt", ".plt.sec", ".plt.got"];

/// What a tool found in one file.
enum Outcome {
    /// Function starts (the file's addresses) and the time taken.
    Found(BTreeSet<u64>, Duration),
    /// The tool did not finish in time.
    Timeout(Duration),
    /// The tool failed or is not installed.
    Failed(String),
}

/// The whole run, as `cfg.json`.
#[derive(Serialize)]
struct Report {
    cpu: String,
    timeout_seconds: u64,
    files: Vec<FileResults>,
}

/// Every tool's result on one file.
#[derive(Serialize)]
struct FileResults {
    name: String,
    path: String,
    format: &'static str,
    /// Function starts the original states (the reference).
    stated: usize,
    /// Whether the tools got a stripped copy (false: nothing to strip).
    stripped: bool,
    results: Vec<ToolResult>,
}

/// One tool's result on one file. The counts and scores are absent unless
/// the status is `ok`.
#[derive(Serialize)]
struct ToolResult {
    tool: String,
    status: Status,
    /// Why there is no score.
    note: Option<String>,
    /// Wall-clock time, up to the timeout if it timed out.
    seconds: f64,
    found: Option<usize>,
    correct: Option<usize>,
    precision: Option<f64>,
    recall: Option<f64>,
    f1: Option<f64>,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Timeout,
    Failed,
}

fn main() -> Result<(), String> {
    let mut tools: Vec<String> = TOOLS.iter().map(|&t| t.to_owned()).collect();
    let mut timeout = Duration::from_secs(600);
    let mut out = PathBuf::from("results");
    let mut files = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--tools" => {
                let list = args.next().ok_or("--tools needs a list")?;
                tools = list.split(',').map(str::to_owned).collect();
            }
            "--timeout" => {
                let seconds = args.next().ok_or("--timeout needs seconds")?;
                timeout = Duration::from_secs(seconds.parse().map_err(|_| "bad --timeout")?);
            }
            "--out" => out = args.next().ok_or("--out needs a directory")?.into(),
            _ => files.push(PathBuf::from(arg)),
        }
    }
    if files.is_empty() {
        return Err("usage: cfg [--tools LIST] [--timeout SECS] [--out DIR] FILE...".to_owned());
    }
    let work = out.join("cfg-work");
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;

    let mut report = Report {
        cpu: cpu(),
        timeout_seconds: timeout.as_secs(),
        files: Vec::new(),
    };
    let path = out.join("cfg.json");
    for file in &files {
        let results = run_file(file, &tools, timeout, &work)?;
        report.files.push(results);
        write_json(&path, &report).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    println!("wrote {}", path.display());
    Ok(())
}

/// Runs every tool on one file and scores it.
fn run_file(
    file: &Path,
    tools: &[String],
    timeout: Duration,
    work: &Path,
) -> Result<FileResults, String> {
    let name = file
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let data = std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let original = Image::parse(&data).map_err(|e| format!("{name}: {e}"))?;
    let stubs: Vec<(u64, u64)> = original
        .sections
        .iter()
        .filter(|s| STUB_SECTIONS.contains(&s.name.as_str()))
        .map(|s| (s.start, s.start + s.size))
        .collect();
    let slots: BTreeSet<u64> = original.imports.iter().map(|import| import.slot).collect();
    // Executable memory, not only code (`Image::is_code`): a function a
    // tool finds in read-only data mapped executable (`.rodata` of a file
    // linked without `-z separate-code`) counts against it.
    let counts = |address: u64| {
        original
            .segment(address)
            .is_some_and(|segment| segment.permissions.execute)
            && !stubs
                .iter()
                .any(|&(start, end)| start <= address && address < end)
            && !import_thunk(&original, &slots, address)
    };
    let truth: BTreeSet<u64> = reference::functions(file, original.format)?
        .into_iter()
        .filter(|&a| counts(a))
        .collect();
    let stripped = strip(file, &original, work)?;

    let mut results = Vec::new();
    for tool in tools {
        let mut result = ToolResult {
            tool: tool.clone(),
            status: Status::Ok,
            note: None,
            seconds: 0.0,
            found: None,
            correct: None,
            precision: None,
            recall: None,
            f1: None,
        };
        match run_tool(tool, &stripped, original.base, timeout, work) {
            Outcome::Found(found, time) => {
                let found: BTreeSet<u64> = found.into_iter().filter(|&a| counts(a)).collect();
                let correct = found.intersection(&truth).count();
                let (precision, recall) =
                    (ratio(correct, found.len()), ratio(correct, truth.len()));
                result.seconds = time.as_secs_f64();
                result.found = Some(found.len());
                result.correct = Some(correct);
                result.precision = Some(precision);
                result.recall = Some(recall);
                result.f1 = Some(if precision + recall > 0.0 {
                    2.0 * precision * recall / (precision + recall)
                } else {
                    0.0
                });
            }
            Outcome::Timeout(time) => {
                result.status = Status::Timeout;
                result.note = Some(format!("timed out after {:.0} s", time.as_secs_f64()));
                result.seconds = time.as_secs_f64();
            }
            Outcome::Failed(message) => {
                result.status = Status::Failed;
                result.note = Some(message);
            }
        }
        match (result.precision, result.recall) {
            (Some(precision), Some(recall)) => println!(
                "{name}: {tool}: precision {:.1}%, recall {:.1}% of {}, {:.2} s",
                precision * 100.0,
                recall * 100.0,
                truth.len(),
                result.seconds
            ),
            _ => println!("{name}: {tool}: {}", result.note.as_deref().unwrap_or("")),
        }
        results.push(result);
    }
    Ok(FileResults {
        name,
        path: file.display().to_string(),
        format: match original.format {
            Format::Elf => "elf",
            Format::Pe => "pe",
            Format::MachO => "macho",
        },
        stated: truth.len(),
        stripped: stripped != file,
        results,
    })
}

/// Whether the code at `address` is an import thunk, `jmp [slot]` through
/// one of the image's import slots (RIP-relative or absolute): PE's
/// counterpart of PLT entries, counted as functions or not by taste and
/// therefore left out on both sides like them.
fn import_thunk(image: &Image<'_>, slots: &BTreeSet<u64>, address: u64) -> bool {
    let Ok(mode) = x86_mode(image.machine) else {
        return false;
    };
    let mut bytes = [0u8; 15];
    let Ok(read) = image.read(address, &mut bytes) else {
        return false;
    };
    let Ok(instruction) = decode(bytes.get(..read).unwrap_or_default(), mode) else {
        return false;
    };
    if instruction.mnemonic() != Mnemonic::Jmp {
        return false;
    }
    let next = address + instruction.len() as u64;
    instruction.operands().any(|operand| match operand.value {
        Value::Memory(memory) if memory.index.is_none() => {
            let slot = match memory.base {
                Some(Register::RIP) => next.wrapping_add_signed(memory.displacement),
                None => memory.displacement.cast_unsigned(),
                Some(_) => return false,
            };
            slots.contains(&slot)
        }
        Value::Memory(_)
        | Value::Register(_)
        | Value::Immediate { .. }
        | Value::SecondImmediate(_)
        | Value::Relative(_)
        | Value::Field(_) => false,
    })
}

fn ratio(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        1.0
    } else {
        part as f64 / whole as f64
    }
}

/// A copy of `file` without symbol tables, or `file` itself if it has none.
fn strip(file: &Path, image: &Image<'_>, work: &Path) -> Result<PathBuf, String> {
    let symbols = image
        .symbols
        .iter()
        .any(|s| s.source == SymbolSource::Static);
    if !symbols {
        return Ok(file.to_owned());
    }
    let name = file.file_name().ok_or("no file name")?;
    let target = work.join("stripped").join(name);
    std::fs::create_dir_all(work.join("stripped")).map_err(|e| e.to_string())?;
    let strip = match image.format {
        Format::Elf => "strip",
        Format::Pe => "x86_64-w64-mingw32-strip",
        Format::MachO => return Err("stripping Mach-O files is not supported".to_owned()),
    };
    let status = Command::new(strip)
        .arg("--strip-all")
        .arg("-o")
        .arg(&target)
        .arg(file)
        .status()
        .map_err(|e| format!("{strip}: {e}"))?;
    if !status.success() {
        return Err(format!("{strip} failed on {}", file.display()));
    }
    Ok(target)
}

/// Runs `tool` on `file` (whose own base is `base`).
fn run_tool(tool: &str, file: &Path, base: u64, timeout: Duration, work: &Path) -> Outcome {
    if tool == "binbun" {
        return binbun(file);
    }
    // radare2 and rizin print to stdout; the others write `output`.
    let output = work.join(format!("{tool}.out"));
    let stdout_path = work.join(format!("{tool}.stdout"));
    let _ = std::fs::remove_file(&output);
    let mut command = match command(tool, file, &output, work) {
        Ok(command) => command,
        Err(message) => return Outcome::Failed(message),
    };
    let Ok(stdout) = std::fs::File::create(&stdout_path) else {
        return Outcome::Failed("cannot create output file".to_owned());
    };
    let started = Instant::now();
    let mut child = match command
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return Outcome::Failed(format!("not runnable: {error}")),
    };
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() > timeout => {
                // The whole group: the child's own children too.
                let _ = Command::new("kill")
                    .args(["-KILL", "--", &format!("-{}", child.id())])
                    .status();
                let _ = child.wait();
                return Outcome::Timeout(started.elapsed());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => return Outcome::Failed(error.to_string()),
        }
    }
    let elapsed = started.elapsed();
    let text = if matches!(tool, "radare2" | "rizin") {
        std::fs::read_to_string(&stdout_path)
    } else {
        std::fs::read_to_string(&output)
    };
    match text {
        Ok(text) => match parse(&text, base) {
            Some(found) => Outcome::Found(found, elapsed),
            None => Outcome::Failed("no base address in output".to_owned()),
        },
        Err(_) => Outcome::Failed("no output".to_owned()),
    }
}

/// The command running external `tool` on `file`, writing to `output`
/// (or stdout); scratch files go to `work`.
fn command(tool: &str, file: &Path, output: &Path, work: &Path) -> Result<Command, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let env = |name: &str, default: String| std::env::var(name).unwrap_or(default);
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command;
    match tool {
        "ida" => {
            let dir = env("IDA_DIR", format!("{home}/ida-pro-9.4"));
            let script = here.join("cfg/ida_functions.py");
            // A fresh database each time (an existing one would be opened).
            let database = work.join("ida-database");
            let _ = std::fs::remove_dir_all(&database);
            let _ = std::fs::create_dir_all(&database);
            command = Command::new(Path::new(&dir).join("idat"));
            command
                .arg("-A")
                .arg(format!("-L{}", work.join("ida.log").display()))
                .arg(format!("-o{}", database.join("ida.i64").display()))
                .arg(format!("-S{} {}", script.display(), output.display()))
                .arg(file);
        }
        "ghidra" => {
            let dir = env("GHIDRA_DIR", "/opt/ghidra".to_owned());
            let project = work.join("ghidra-project");
            let _ = std::fs::remove_dir_all(&project);
            let _ = std::fs::create_dir_all(&project);
            command = Command::new(Path::new(&dir).join("support/analyzeHeadless"));
            command
                .arg(&project)
                .arg("binbun")
                .arg("-import")
                .arg(file)
                .arg("-scriptPath")
                .arg(here.join("cfg/ghidra"))
                .arg("-postScript")
                .arg("ListFunctions.java")
                .arg(output)
                .arg("-deleteProject");
        }
        "angr" => {
            command = Command::new(env(
                "ANGR_PYTHON",
                format!("{home}/.cache/binbun/angr-venv/bin/python"),
            ));
            command
                .arg(here.join("cfg/angr_functions.py"))
                .arg(file)
                .arg(output);
        }
        "radare2" | "rizin" => {
            command = Command::new(if tool == "radare2" { "r2" } else { "rizin" });
            command
                .args(["-q", "-e", "scr.color=0", "-c", "iI~baddr; aaa; afl"])
                .arg(file);
        }
        "falcon" => {
            let default = here.join("falcon/target/release/falcon-functions");
            command = Command::new(env("FALCON_FUNCTIONS", default.display().to_string()));
            command.arg(file).arg(output);
        }
        other => return Err(format!("unknown tool {other}")),
    }
    Ok(command)
}

/// Function starts from a tool's output: a base address (`=` for the
/// file's own; `baddr 0x...` from radare2 and rizin), then one hex address
/// at the start of each line, moved to the file's base `base`.
fn parse(text: &str, base: u64) -> Option<BTreeSet<u64>> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let first = lines.next()?.trim();
    let first = first.strip_prefix("baddr").unwrap_or(first).trim();
    let tool_base = if first == "=" { base } else { hex(first)? };
    Some(
        lines
            .filter_map(|line| hex(line.split_whitespace().next()?))
            .map(|address| address.wrapping_sub(tool_base).wrapping_add(base))
            .collect(),
    )
}

fn hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

/// binbun, in process: load, then recover from everything the stripped
/// file states.
fn binbun(file: &Path) -> Outcome {
    let started = Instant::now();
    let Ok(data) = std::fs::read(file) else {
        return Outcome::Failed("cannot read".to_owned());
    };
    let image = match Image::parse(&data) {
        Ok(image) => image,
        Err(error) => return Outcome::Failed(error.to_string()),
    };
    let library = match type_library(&image) {
        Ok(library) => library,
        Err(error) => return Outcome::Failed(format!("type library: {error}")),
    };
    match analyse(&image, Seeds::ALL, &library) {
        Ok(program) => {
            // Parts joined into their function (cold parts) count by
            // their starts, as the unwind entries the truth has them by.
            let found = program
                .functions
                .values()
                .flat_map(|f| std::iter::once(f.entry).chain(f.parts.iter().copied()))
                .collect();
            Outcome::Found(found, started.elapsed())
        }
        Err(error) => Outcome::Failed(format!("{:?} is not supported", error.0)),
    }
}
