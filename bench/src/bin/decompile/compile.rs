//! Whether each tool's C for a function compiles, in three settings:
//!
//! - `own`: the file the tool's own declarations make ([`crate::tools`]),
//!   with the tool's header: binbun's `binbun_defs.h`, Hex-Rays' `defs.h` from
//!   IDA's `include/`, Ghidra's export header (its items the function
//!   uses), and for angr, which has none, DecompileBench's `defs.h` for
//!   angr;
//! - `decompilebench`: DecompileBench's (evaluate_rsr.py): its `defs.h`
//!   for the tool (`fix/TOOL/defs.h`) included before the function's text
//!   alone, not binbun's (DecompileBench has no header for it);
//! - `libc`: the `own` file after `_GNU_SOURCE` and the C library's
//!   common headers, for C that names the library's types and functions
//!   without declaring them.
//!
//! Each compiles as one translation unit, `-std=gnu17 -O0 -fPIC -fwrapv
//! -fno-strict-aliasing -c`, read unmodified from standard input: strictly
//! (the compiler's default errors; with clang also as C23, `-std=gnu23`),
//! and under DecompileBench's rule (a
//! file that fails is compiled again with `-Wno-X` for each `[-WX]` its
//! diagnostics name, which turns off the warnings clang and gcc make
//! errors by default, such as implicit declarations). clang also gets
//! `-fno-spell-checking` (no verdict changes; typo correction makes a few
//! files take minutes), and each compile 60 s at most.

use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::tools::Text;

/// The flags every file is compiled with.
pub const FLAGS: [&str; 7] = [
    "-std=gnu17",
    "-O0",
    "-fPIC",
    "-fwrapv",
    "-fno-strict-aliasing",
    "-fdiagnostics-color=never",
    "-c",
];

/// What the `libc` setting puts before the `own` file.
pub const LIBC_PRELUDE: &str = "#define _GNU_SOURCE\n\
#include <ctype.h>\n#include <dirent.h>\n#include <dlfcn.h>\n#include <errno.h>\n\
#include <fcntl.h>\n#include <grp.h>\n#include <iconv.h>\n#include <langinfo.h>\n\
#include <limits.h>\n#include <locale.h>\n#include <math.h>\n#include <pwd.h>\n\
#include <setjmp.h>\n#include <signal.h>\n#include <stdarg.h>\n#include <stddef.h>\n\
#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\
#include <sys/resource.h>\n#include <sys/stat.h>\n#include <sys/time.h>\n\
#include <sys/types.h>\n#include <sys/wait.h>\n#include <termios.h>\n#include <time.h>\n\
#include <unistd.h>\n#include <wchar.h>\n#include <wctype.h>\n";

/// The settings, in the order the behaviour test tries them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Setting {
    Own,
    Libc,
    Decompilebench,
}

/// Where the headers are.
pub struct Headers {
    /// A directory holding `binbun_defs.h`.
    pub binbun: PathBuf,
    /// IDA's `include/` (Hex-Rays' `defs.h`).
    pub ida: PathBuf,
    /// DecompileBench's headers: `TOOL/defs.h`.
    pub decompilebench: PathBuf,
}

/// The file and include directories of `text` (a function of `tool`) in
/// `setting`, if the setting applies to the tool.
pub fn source(
    tool: &str,
    setting: Setting,
    text: &Text,
    headers: &Headers,
) -> Option<(String, Vec<PathBuf>)> {
    let Text::C { own, function } = text else {
        return None;
    };
    let own_includes = match tool {
        "binbun" | "binbun-reading" => vec![headers.binbun.clone()],
        "hexrays" => vec![headers.ida.clone()],
        "angr" => vec![headers.decompilebench.join("angr")],
        _ => Vec::new(),
    };
    match setting {
        Setting::Own => Some((own.clone(), own_includes)),
        Setting::Libc => Some((format!("{LIBC_PRELUDE}{own}"), own_includes)),
        Setting::Decompilebench => match tool {
            "hexrays" | "ghidra" | "angr" => Some((
                format!("#include <defs.h>\n{function}"),
                vec![headers.decompilebench.join(tool)],
            )),
            _ => None,
        },
    }
}

/// How long one compile may take (a few files make clang take minutes).
const COMPILE_TIMEOUT: Duration = Duration::from_secs(60);

/// Compiles `source` with `compiler` and `extra` flags: its diagnostics if
/// it fails or takes over [`COMPILE_TIMEOUT`].
pub fn compile(
    compiler: &str,
    source: &str,
    includes: &[PathBuf],
    extra: &[String],
    output: Option<&std::path::Path>,
) -> Result<(), String> {
    let mut command = Command::new(compiler);
    command.args(FLAGS).args(extra);
    if compiler == "clang" {
        // Typo correction makes clang take minutes on a few long files
        // full of undeclared names; it changes no verdict.
        command.arg("-fno-spell-checking");
    }
    for include in includes {
        command.arg("-I").arg(include);
    }
    command
        .args(["-x", "c", "-", "-o"])
        .arg(output.map_or_else(|| PathBuf::from("/dev/null"), std::path::Path::to_path_buf))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| format!("{compiler}: {e}"))?;
    let stdin = child.stdin.take();
    let text = source.to_owned();
    // A compiler that stops reading early (a fatal error) closes the pipe:
    // its verdict stands.
    let writer = std::thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(text.as_bytes());
        }
    });
    let mut stderr = child.stderr.take();
    let reader = std::thread::spawn(move || {
        let mut diagnostics = Vec::new();
        if let Some(stderr) = stderr.as_mut() {
            let _ = stderr.read_to_end(&mut diagnostics);
        }
        diagnostics
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() > COMPILE_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => return Err(format!("{compiler}: {error}")),
        }
    };
    let _ = writer.join();
    let diagnostics = String::from_utf8_lossy(&reader.join().unwrap_or_default()).into_owned();
    match status {
        Some(status) if status.success() => Ok(()),
        Some(_) => Err(diagnostics),
        None => Err(format!(
            "<stdin>: error: the compiler took over {} s\n{diagnostics}",
            COMPILE_TIMEOUT.as_secs()
        )),
    }
}

/// The `-Wno-X` flags DecompileBench's rule adds after `diagnostics`: one
/// per line naming `[-WX]` (its regular expression `\[-W(.*)\]`, greedy
/// within a line).
pub fn lenient_flags(diagnostics: &str) -> Vec<String> {
    let mut flags: Vec<String> = diagnostics
        .lines()
        .filter_map(|line| {
            let start = line.find("[-W")?;
            let end = line.rfind(']')?;
            (end > start + 3).then(|| format!("-Wno-{}", &line[start + 3..end]))
        })
        .collect();
    flags.sort();
    flags.dedup();
    flags
}

/// Compiles under DecompileBench's rule: strictly, then (if that fails
/// and the diagnostics name warnings) again with them off. The flags it
/// took (`base` and those), if it compiles.
pub fn lenient(
    compiler: &str,
    source: &str,
    includes: &[PathBuf],
    base: &[String],
) -> Result<Vec<String>, String> {
    match compile(compiler, source, includes, base, None) {
        Ok(()) => Ok(base.to_vec()),
        Err(diagnostics) => {
            let added = lenient_flags(&diagnostics);
            if added.is_empty() {
                return Err(diagnostics);
            }
            let mut flags = base.to_vec();
            flags.extend(added);
            compile(compiler, source, includes, &flags, None).map(|()| flags)
        }
    }
}

/// A compiler's first error, as a category: the message with what it
/// quotes and its warning flag left out (`unknown type name '…'`).
pub fn category(diagnostics: &str) -> String {
    let Some(line) = diagnostics
        .lines()
        .find(|line| !line.starts_with(' ') && line.contains("error: "))
    else {
        return "no error message".to_owned();
    };
    let message = &line[line.find("error: ").map_or(0, |at| at + 7)..];
    let message = message.split(" [-W").next().unwrap_or(message);
    let message = message.split("; ").next().unwrap_or(message);
    let mut out = String::new();
    let mut quoted = false;
    for c in message.chars() {
        match c {
            '\'' | '‘' | '’' => {
                if !quoted {
                    out.push_str("'…'");
                }
                quoted = !quoted;
            }
            _ if quoted => {}
            c => out.push(c),
        }
    }
    out.trim().to_owned()
}

/// Every verdict on one function of one tool.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Compiled {
    /// `own` with clang, C17 (`-std=gnu17`).
    pub own_clang: bool,
    /// `own` with clang, C23 (`-std=gnu23`: `nullptr`, `bool`; `f()` means
    /// `f(void)`).
    pub own_c23: bool,
    pub own_gcc: bool,
    /// `own` with clang under DecompileBench's rule, C17.
    pub own_lenient: bool,
    pub libc_lenient: bool,
    /// DecompileBench's setting (none for binbun).
    pub decompilebench: Option<bool>,
    /// clang's first error on the `own` file (C17), as a category.
    pub error: Option<String>,
    /// The first setting that compiles, as the behaviour test takes it
    /// (`own` strictly in C17 then C23, leniently in C17 then C23, then
    /// `libc`, then `decompilebench`), with the flags it took.
    pub chosen: Option<(Setting, Vec<String>)>,
}

impl Compiled {
    pub fn any(&self) -> bool {
        self.chosen.is_some()
    }
}

/// All verdicts on `text`, a function of `tool`.
pub fn verdicts(tool: &str, text: &Text, headers: &Headers) -> Compiled {
    let mut compiled = Compiled::default();
    let Some((own, includes)) = source(tool, Setting::Own, text, headers) else {
        return compiled;
    };
    let c23 = vec!["-std=gnu23".to_owned()];
    fn choose(compiled: &mut Compiled, setting: Setting, flags: Vec<String>) {
        if compiled.chosen.is_none() {
            compiled.chosen = Some((setting, flags));
        }
    }
    match compile("clang", &own, &includes, &[], None) {
        Ok(()) => {
            compiled.own_clang = true;
            choose(&mut compiled, Setting::Own, Vec::new());
        }
        Err(diagnostics) => compiled.error = Some(category(&diagnostics)),
    }
    if compile("clang", &own, &includes, &c23, None).is_ok() {
        compiled.own_c23 = true;
        choose(&mut compiled, Setting::Own, c23.clone());
    }
    if let Ok(flags) = lenient("clang", &own, &includes, &[]) {
        compiled.own_lenient = true;
        choose(&mut compiled, Setting::Own, flags);
    }
    if compiled.chosen.is_none()
        && let Ok(flags) = lenient("clang", &own, &includes, &c23)
    {
        choose(&mut compiled, Setting::Own, flags);
    }
    compiled.own_gcc = compile("gcc", &own, &includes, &[], None).is_ok();
    if let Some((libc, includes)) = source(tool, Setting::Libc, text, headers)
        && let Ok(flags) = lenient("clang", &libc, &includes, &[])
    {
        compiled.libc_lenient = true;
        choose(&mut compiled, Setting::Libc, flags);
    }
    if let Some((bench, includes)) = source(tool, Setting::Decompilebench, text, headers) {
        let result = lenient("clang", &bench, &includes, &[]);
        if let Ok(flags) = &result {
            choose(&mut compiled, Setting::Decompilebench, flags.clone());
        }
        compiled.decompilebench = Some(result.is_ok());
    }
    compiled
}
