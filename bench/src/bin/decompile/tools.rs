//! Each decompiler run on a whole file, its C split into functions by
//! entry address (the file's own addresses), with the names it gave
//! addresses and the file each function compiles as.
//!
//! - binbun: `binbun decompile FILE` (`BINBUN`, default `binbun` on the
//!   path), exact C and `--view reading`, each a file per function
//!   including `binbun_defs.h`.
//! - Hex-Rays (only with `--private`: [`tools`]): `idat` with
//!   `ida_decompile.py` (IDA's File > Produce file > Create C file); a
//!   function's file is `defs.h` and the declarations the produced file
//!   has for what the function uses, then the function.
//! - Ghidra: `analyzeHeadless` with `ghidra/DecompileAll.java` (what File >
//!   Export Program > C/C++ writes, per function); a function's file is
//!   the export header's items it uses, the globals it references, then the
//!   function.
//! - angr: `angr_decompile.py` (DecompileBench's runner setup), in
//!   parallel shards; a function's file is DecompileBench's `defs.h` for
//!   angr and the function (whose text declares its globals and structs).
//! - Binary Ninja (only with `--private`, where `BINJA_MCP` is set):
//!   `binja_mcp.py`, through the MCP server its GUI hosts (the free
//!   edition has no API and no headless mode); a function's file is the
//!   items it uses of a header made of the view's types, data variables
//!   and prototypes, then its Pseudo C. Its time is from opening the
//!   file to the last function's Pseudo C, the GUI's threads on the
//!   harness's CPUs meanwhile: its startup is not in it (the GUI is up
//!   already), a request per function is.

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::cparse::Declarations;

/// The tools whose results are published, as the reports name them.
pub const TOOLS: [&str; 4] = ["binbun", "binbun-reading", "ghidra", "angr"];

/// [`TOOLS`]; when `private`, also Hex-Rays, and Binary Ninja where
/// `BINJA_MCP` names the MCP server of a running one (it cannot be started
/// from here), in the order the reports list them. Their licences restrict
/// publishing their results (`docs/benchmarks.md`).
pub fn tools(private: bool) -> Vec<String> {
    let mut tools: Vec<String> = TOOLS.iter().map(|&tool| tool.to_owned()).collect();
    if !private {
        return tools;
    }
    tools.insert(2, "hexrays".to_owned());
    if std::env::var_os("BINJA_MCP").is_some() {
        let at = tools
            .iter()
            .position(|tool| tool == "angr")
            .unwrap_or(tools.len());
        tools.insert(at, "binja".to_owned());
    }
    tools
}

/// One function's C from one tool.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Text {
    C {
        /// The file the tool's own declarations make (setting `own`).
        own: String,
        /// The function's own text.
        function: String,
    },
    /// The tool has the function but gave no C, and why.
    Failed(String),
}

/// One tool's run over one file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decompilation {
    pub tool: String,
    pub version: String,
    /// Wall-clock seconds for the whole file, startup included (absent
    /// for angr's sharded run, timed apart).
    pub seconds: Option<f64>,
    /// Each function by entry.
    pub functions: BTreeMap<u64, Text>,
    /// The names the tool gave addresses (the file's own).
    pub names: BTreeMap<String, u64>,
}

/// Where the tools are, as the function recovery benchmark finds them.
pub struct Places {
    /// The `binbun` command.
    pub binbun: PathBuf,
    pub ida: PathBuf,
    pub ghidra: PathBuf,
    pub angr_python: PathBuf,
    /// A directory for Ghidra's projects: a path without an element
    /// starting with `.` (Ghidra refuses those).
    pub ghidra_projects: PathBuf,
    /// The URL of the MCP server a running Binary Ninja hosts.
    pub binja_mcp: String,
}

impl Places {
    pub fn from_environment(work: &Path) -> Self {
        let home = std::env::var("HOME").unwrap_or_default();
        let env = |name: &str, default: String| std::env::var(name).unwrap_or(default);
        Self {
            binbun: env("BINBUN", "binbun".to_owned()).into(),
            ida: env("IDA_DIR", format!("{home}/ida-pro-9.4")).into(),
            ghidra: env("GHIDRA_DIR", "/opt/ghidra".to_owned()).into(),
            angr_python: env(
                "ANGR_PYTHON",
                format!("{home}/.cache/binbun/angr-venv/bin/python"),
            )
            .into(),
            ghidra_projects: std::env::var_os("GHIDRA_PROJECTS")
                .map_or_else(|| work.join("ghidra-projects"), PathBuf::from),
            binja_mcp: env("BINJA_MCP", "http://127.0.0.1:24642/mcp".to_owned()),
        }
    }
}

fn scripts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("decompile")
}

/// How a command ended.
pub enum Ended {
    Done(Duration),
    Failed(Duration, String),
    Timeout(Duration),
}

/// Runs `command` in its own process group (killed as a whole after
/// `timeout`), its standard output to `log`, its standard error to `log`
/// with `.stderr` appended.
pub fn run(mut command: Command, log: &Path, timeout: Duration) -> Ended {
    let Ok(out) = std::fs::File::create(log) else {
        return Ended::Failed(Duration::ZERO, format!("cannot create {}", log.display()));
    };
    let mut err_path = log.as_os_str().to_owned();
    err_path.push(".stderr");
    let Ok(err) = std::fs::File::create(&err_path) else {
        return Ended::Failed(Duration::ZERO, "cannot create the error log".to_owned());
    };
    let started = Instant::now();
    let mut child = match command
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .process_group(0)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return Ended::Failed(Duration::ZERO, format!("not runnable: {error}")),
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ended::Done(started.elapsed()),
            Ok(Some(status)) => {
                return Ended::Failed(started.elapsed(), format!("exited with {status}"));
            }
            Ok(None) if started.elapsed() > timeout => {
                let _ = Command::new("kill")
                    .args(["-KILL", "--", &format!("-{}", child.id())])
                    .status();
                let _ = child.wait();
                return Ended::Timeout(started.elapsed());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => return Ended::Failed(started.elapsed(), error.to_string()),
        }
    }
}

/// `binbun decompile FILE` (`--view reading` for the reading view) at
/// `places.binbun`, scratch files in `work`: each function's C (the
/// command prints a file per function, after a line `/* NAME at 0xADDR,
/// decompiled by binbun. */`, or `/* 0xADDR NAME: not decompiled: WHY */`),
/// timed whole.
pub fn binbun(
    file: &Path,
    reading: bool,
    places: &Places,
    work: &Path,
    timeout: Duration,
) -> Result<Decompilation, String> {
    std::fs::create_dir_all(work).map_err(|e| e.to_string())?;
    let tool = if reading { "binbun-reading" } else { "binbun" };
    let out = work.join(format!("{tool}.c"));
    let mut command = Command::new(&places.binbun);
    command.arg("decompile").arg(file);
    if reading {
        command.args(["--view", "reading"]);
    }
    let seconds = finished(run(command, &out, timeout), "binbun")?;
    let text = std::fs::read_to_string(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let _ = std::fs::remove_file(&out);
    let version = Command::new(&places.binbun)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| "binbun".to_owned(), |v| v.trim().to_owned());
    let mut functions = BTreeMap::new();
    let mut current: Option<(u64, String)> = None;
    fn finish(current: Option<(u64, String)>, functions: &mut BTreeMap<u64, Text>) {
        if let Some((entry, own)) = current {
            functions.insert(
                entry,
                Text::C {
                    function: own.clone(),
                    own,
                },
            );
        }
    }
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end();
        let header = trimmed
            .strip_prefix("/* ")
            .and_then(|l| l.strip_suffix(", decompiled by binbun. */"))
            .and_then(|l| l.rsplit_once(" at 0x"))
            .and_then(|(_, hex)| u64::from_str_radix(hex, 16).ok());
        let failed = trimmed
            .strip_prefix("/* 0x")
            .filter(|l| l.contains(": not decompiled: "))
            .and_then(|l| {
                let (hex, rest) = l.split_once(' ')?;
                let why = rest.split_once(": not decompiled: ")?.1;
                Some((
                    u64::from_str_radix(hex, 16).ok()?,
                    why.trim_end_matches(" */").to_owned(),
                ))
            });
        if let Some(entry) = header {
            finish(current.take(), &mut functions);
            current = Some((entry, line.to_owned()));
        } else if let Some((entry, why)) = failed {
            finish(current.take(), &mut functions);
            functions.insert(entry, Text::Failed(why));
        } else if let Some((_, own)) = current.as_mut() {
            own.push_str(line);
        }
    }
    finish(current.take(), &mut functions);
    Ok(Decompilation {
        tool: tool.to_owned(),
        version,
        seconds: Some(seconds),
        functions,
        names: BTreeMap::new(),
    })
}

/// Hex-Rays on `file`, scratch files in `work`.
pub fn hexrays(
    file: &Path,
    places: &Places,
    work: &Path,
    timeout: Duration,
) -> Result<Decompilation, String> {
    std::fs::create_dir_all(work).map_err(|e| e.to_string())?;
    let out = work.join("ida");
    let database = work.join("ida-database");
    let _ = std::fs::remove_dir_all(&database);
    std::fs::create_dir_all(&database).map_err(|e| e.to_string())?;
    let mut command = Command::new(places.ida.join("idat"));
    command
        .arg("-A")
        .arg(format!("-L{}", work.join("ida.log").display()))
        .arg(format!("-o{}", database.join("ida.i64").display()))
        .arg(format!(
            "-S{} {}",
            scripts().join("ida_decompile.py").display(),
            out.display()
        ))
        .arg(file);
    let seconds = finished(run(command, &work.join("ida.stdout"), timeout), "Hex-Rays")?;
    let _ = std::fs::remove_dir_all(&database);
    let read = |suffix: &str| {
        let path = out.with_extension(suffix);
        std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
    };
    let c = read("c")?;
    let version = format!("Hex-Rays {}", read("version")?.trim());
    let names = names(&read("names")?);
    // The produced file: its declarations, then each function after a
    // `//----- (ADDRESS) ---` line.
    let marker = "//----- (";
    let first = c.find(&format!("\n{marker}")).map_or(c.len(), |at| at + 1);
    let preamble = &c[..first];
    let declarations = Declarations::new(preamble);
    let mut functions = BTreeMap::new();
    let mut rest = &c[first..];
    while let Some(line_end) = rest.find('\n') {
        let header = &rest[..line_end];
        let Some(address) = header
            .strip_prefix(marker)
            .and_then(|h| h.split(')').next())
            .and_then(|h| u64::from_str_radix(h, 16).ok())
        else {
            break;
        };
        let body_start = line_end + 1;
        let next = rest[body_start..]
            .find(&format!("\n{marker}"))
            .map_or(rest.len(), |at| body_start + at + 1);
        let function = rest[body_start..next].to_owned();
        let own = format!("{}\n{function}", declarations.needed(&function));
        functions.insert(address, Text::C { own, function });
        rest = &rest[next..];
    }
    Ok(Decompilation {
        tool: "hexrays".to_owned(),
        version,
        seconds: Some(seconds),
        functions,
        names,
    })
}

/// Ghidra on `file`, scratch files in `work`.
pub fn ghidra(
    file: &Path,
    places: &Places,
    work: &Path,
    timeout: Duration,
) -> Result<Decompilation, String> {
    let out = work.join("ghidra");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let project = places.ghidra_projects.join("decompile");
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).map_err(|e| e.to_string())?;
    let mut command = Command::new(places.ghidra.join("support/analyzeHeadless"));
    command
        .arg(&project)
        .arg("binbun")
        .arg("-import")
        .arg(file)
        .arg("-scriptPath")
        .arg(scripts().join("ghidra"))
        .arg("-postScript")
        .arg("DecompileAll.java")
        .arg(&out)
        .arg("-deleteProject");
    let seconds = finished(run(command, &work.join("ghidra.log"), timeout), "Ghidra")?;
    let _ = std::fs::remove_dir_all(&project);
    let read = |name: &str| {
        let path = out.join(name);
        std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
    };
    let version = format!("Ghidra {}", read("version.txt")?.trim());
    let header = read("header.h")?;
    let declarations = Declarations::new(&header);
    let names = names(&read("names.txt")?);
    let mut functions = BTreeMap::new();
    for (address, chunk) in chunks(&read("functions.c")?) {
        if let Some(why) = chunk.strip_prefix("//@failed ") {
            functions.insert(address, Text::Failed(why.trim().to_owned()));
            continue;
        }
        let mut globals = String::new();
        let mut body = chunk;
        while let Some(rest) = body.strip_prefix("//@global ") {
            let end = rest.find('\n').map_or(rest.len(), |e| e + 1);
            // A function whose address is taken comes among the globals
            // too, as `undefined f;`: the header's prototype declares it.
            let name = rest[..end]
                .trim_end()
                .trim_end_matches(';')
                .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .next()
                .unwrap_or_default();
            if !declarations.declares(name) {
                // The script writes a type's name, then the global's:
                // an array's size goes after the name in C.
                match rest[..end].trim_end().rsplit_once(' ') {
                    Some((ty, declared)) if ty.ends_with(']') && ty.contains('[') => {
                        let (element, size) = ty.split_at(ty.find('[').unwrap_or(ty.len()));
                        let declared = declared.trim_end_matches(';');
                        globals.push_str(&format!("{element} {declared}{size};\n"));
                    }
                    Some(_) | None => globals.push_str(&rest[..end]),
                }
            }
            body = &rest[end..];
        }
        let function = body.to_owned();
        let own = format!(
            "{}\n{globals}\n{function}",
            declarations.needed(&format!("{globals}\n{function}"))
        );
        functions.insert(address, Text::C { own, function });
    }
    Ok(Decompilation {
        tool: "ghidra".to_owned(),
        version,
        seconds: Some(seconds),
        functions,
        names,
    })
}

/// Binary Ninja on `file` through the MCP server at `places.binja_mcp`,
/// scratch files in `work`, timed by the script (open to the last
/// function).
pub fn binja(
    file: &Path,
    places: &Places,
    work: &Path,
    timeout: Duration,
) -> Result<Decompilation, String> {
    let out = work.join("binja");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let mut command = Command::new("python3");
    command
        .arg(scripts().join("binja_mcp.py"))
        .arg(file)
        .arg(&out)
        .arg(&places.binja_mcp);
    finished(
        run(command, &work.join("binja.log"), timeout),
        "Binary Ninja",
    )?;
    let read = |name: &str| {
        let path = out.join(name);
        std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
    };
    let version = format!("Binary Ninja {}", read("version.txt")?.trim());
    let seconds = read("seconds.txt")?
        .trim()
        .parse()
        .map_err(|_| "Binary Ninja: no time".to_owned())?;
    let declarations = Declarations::new(&read("header.h")?);
    let names = names(&read("names.txt")?);
    let mut functions = BTreeMap::new();
    for (address, chunk) in chunks(&read("functions.c")?) {
        let text = match chunk.strip_prefix("//@failed ") {
            Some(why) => Text::Failed(why.trim().to_owned()),
            None => Text::C {
                own: format!("{}\n{chunk}", declarations.needed(chunk)),
                function: chunk.to_owned(),
            },
        };
        functions.insert(address, text);
    }
    Ok(Decompilation {
        tool: "binja".to_owned(),
        version,
        seconds: Some(seconds),
        functions,
        names,
    })
}

/// angr on `file` in `shards` processes at once (each function given up
/// after `per_function` seconds), scratch files in `work`: not timed (its
/// whole-file time is [`angr_timed`]'s).
pub fn angr(
    file: &Path,
    places: &Places,
    work: &Path,
    shards: usize,
    per_function: u64,
) -> Result<Decompilation, String> {
    let out = work.join("angr");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let handles: Vec<_> = (0..shards)
        .map(|shard| {
            let mut command = Command::new(&places.angr_python);
            command
                .arg(scripts().join("angr_decompile.py"))
                .arg(file)
                .arg(out.join(format!("s{shard}")))
                .arg(shard.to_string())
                .arg(shards.to_string())
                .arg(per_function.to_string());
            let log = out.join(format!("s{shard}.log"));
            std::thread::spawn(move || run(command, &log, Duration::from_secs(86_400)))
        })
        .collect();
    for (shard, handle) in handles.into_iter().enumerate() {
        match handle.join() {
            Ok(Ended::Done(_)) => {}
            Ok(Ended::Failed(_, why)) => return Err(format!("angr shard {shard}: {why}")),
            Ok(Ended::Timeout(_)) => return Err(format!("angr shard {shard} timed out")),
            Err(_) => return Err(format!("angr shard {shard} panicked")),
        }
    }
    let read = |name: &str| {
        let path = out.join(name);
        std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
    };
    let version = format!("angr {}", read("s0.version")?.trim());
    let names = names(&read("s0.names")?);
    let mut functions = BTreeMap::new();
    for shard in 0..shards {
        for (address, chunk) in chunks(&read(&format!("s{shard}.c"))?) {
            let text = match chunk.strip_prefix("//@failed ") {
                Some(why) => Text::Failed(why.trim().to_owned()),
                None => Text::C {
                    own: format!("#include <defs.h>\n{chunk}"),
                    function: chunk.to_owned(),
                },
            };
            functions.insert(address, text);
        }
    }
    Ok(Decompilation {
        tool: "angr".to_owned(),
        version,
        seconds: None,
        functions,
        names,
    })
}

/// angr on the whole of `file` in one process (as its runner decompiles a
/// binary), timed.
pub fn angr_timed(file: &Path, places: &Places, work: &Path, timeout: Duration) -> Ended {
    let out = work.join("angr-timed");
    let _ = std::fs::create_dir_all(&out);
    let mut command = Command::new(&places.angr_python);
    command
        .arg(scripts().join("angr_decompile.py"))
        .arg(file)
        .arg(out.join("all"));
    let ended = run(command, &out.join("log"), timeout);
    let _ = std::fs::remove_dir_all(&out);
    ended
}

/// A tool on the whole of `file`, timed only (its output removed).
pub fn timed(tool: &str, file: &Path, places: &Places, work: &Path, timeout: Duration) -> Ended {
    let work = work.join(format!("{tool}-timed"));
    let _ = std::fs::create_dir_all(&work);
    let ended = match tool {
        "binbun" | "binbun-reading" => {
            match binbun(file, tool == "binbun-reading", places, &work, timeout) {
                Ok(d) => Ended::Done(Duration::from_secs_f64(d.seconds.unwrap_or(0.0))),
                Err(why) => ended_from(&why),
            }
        }
        "hexrays" => match hexrays(file, places, &work, timeout) {
            Ok(d) => Ended::Done(Duration::from_secs_f64(d.seconds.unwrap_or(0.0))),
            Err(why) => ended_from(&why),
        },
        "ghidra" => match ghidra(file, places, &work, timeout) {
            Ok(d) => Ended::Done(Duration::from_secs_f64(d.seconds.unwrap_or(0.0))),
            Err(why) => ended_from(&why),
        },
        "binja" => match binja(file, places, &work, timeout) {
            Ok(d) => Ended::Done(Duration::from_secs_f64(d.seconds.unwrap_or(0.0))),
            Err(why) => ended_from(&why),
        },
        _ => angr_timed(file, places, &work, timeout),
    };
    let _ = std::fs::remove_dir_all(&work);
    ended
}

/// A timeout said in an error ([`finished`]'s) back as [`Ended`].
fn ended_from(why: &str) -> Ended {
    match why
        .strip_prefix("timed out after ")
        .and_then(|s| s.strip_suffix(" s"))
        .and_then(|s| s.parse::<f64>().ok())
    {
        Some(seconds) => Ended::Timeout(Duration::from_secs_f64(seconds)),
        None => Ended::Failed(Duration::ZERO, why.to_owned()),
    }
}

/// The seconds a finished run took, or why it has no output.
fn finished(ended: Ended, tool: &str) -> Result<f64, String> {
    match ended {
        Ended::Done(time) => Ok(time.as_secs_f64()),
        Ended::Failed(_, why) => Err(format!("{tool}: {why}")),
        Ended::Timeout(time) => Err(format!("timed out after {:.0} s", time.as_secs_f64())),
    }
}

/// A tool's name list: a base (`=` for addresses already the file's own,
/// else hex), then `address name` lines; names to addresses moved to the
/// file's base (0 for the shared objects and executables here). A name
/// given twice keeps its first address.
fn names(text: &str) -> BTreeMap<String, u64> {
    let mut lines = text.lines();
    let base = match lines.next().map(str::trim) {
        Some("=") | None => 0,
        Some(base) => u64::from_str_radix(base, 16).unwrap_or(0),
    };
    let mut names = BTreeMap::new();
    for line in lines {
        if let Some((address, name)) = line.split_once(' ')
            && let Ok(address) = u64::from_str_radix(address, 16)
        {
            names
                .entry(name.trim().to_owned())
                .or_insert(address.wrapping_sub(base));
        }
    }
    names
}

/// The functions of a file of `//@bench ADDRESS` markers, each with the
/// text up to the next.
fn chunks(text: &str) -> Vec<(u64, &str)> {
    let marker = "//@bench ";
    let mut found = Vec::new();
    let mut starts: Vec<usize> = text.match_indices(marker).map(|(at, _)| at).collect();
    starts.retain(|&at| at == 0 || text.as_bytes()[at - 1] == b'\n');
    for (index, &start) in starts.iter().enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(text.len());
        let chunk = &text[start + marker.len()..end];
        let (address, body) = chunk.split_once('\n').unwrap_or((chunk, ""));
        if let Ok(address) = u64::from_str_radix(address.trim(), 16) {
            found.push((address, body));
        }
    }
    found
}
