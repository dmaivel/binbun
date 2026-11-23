//! `binbun`'s commands: functions, control-flow graphs, C, strings and
//! cross-references of ELF, PE and Mach-O executables, through the engine
//! ([`binbun::Database`]).
//!
//! ```text
//! binbun [FILE]                      the GUI, FILE open in it (where
//!                                    binbun was built with it)
//! binbun functions FILE              every recovered function
//! binbun cfg FILE FUNCTION [--dot]   one function's blocks (by name or address)
//!                                    and exception tables
//! binbun graph FILE FUNCTION [--svg OUT]
//!                                    one function's graph laid out as the
//!                                    GUI draws it ([`binbun::graph`]), its
//!                                    layout timed and measured
//! binbun eval [--seeds entry|all] [--no-pointers] FILE...
//! binbun eval types FILE [--debug PATH] [--totals]
//!                                    the decompiler's types against debug
//!                                    information ([`crate::score`])
//! binbun decompile FILE [FUNCTION...] [--style PRESET] [--l2] [--stats]
//!                  [--disable-pass NAME]... [--debug PATH]
//!                  [--view exact|reading] [--symbols[=always|never]]
//!                  [--types fixed|plain] [--declarations scoped|top]
//!                  [--names numbered|registers]
//! binbun strings FILE [--min N] [--referenced]
//! binbun xrefs FILE TARGET           references to a name or address
//! binbun xrefs FILE --from FUNCTION  what a function refers to
//! binbun run FILE FUNCTION --state STATE.toml [--view exact|reading]
//!            [--types fixed|plain] [--declarations scoped|top]
//!            [--names numbered|registers] [--depth N] [--steps N]
//!            [--profile NAME|PATH]
//!                                    one function run from an example
//!                                    state, its C with each line's values,
//!                                    on a processor's profile if given
//! binbun verify FILE [FUNCTION] [--view exact|reading] [--states N] [--shaped N]
//!               [--seed N] [--fuel N] [--project DIR] [--profile NAME|PATH]
//!                                    a function (or every one) checked
//!                                    against its L1 ([`binbun::queries::verify`]),
//!                                    recovered with the corrections of
//!                                    the project in DIR, on a processor's
//!                                    profile if given
//! binbun verify FILE [FUNCTION] --compare PROFILE,PROFILE... [--states N]
//!               [--shaped N] [--seed N] [--fuel N] [--save DIR]
//!               [--states-full]
//!                                    whether the function (or which ones)
//!                                    behaves differently on these
//!                                    processors ([`binbun::queries::compare`]):
//!                                    an example state per way they
//!                                    differ, each whole with
//!                                    --states-full
//!                                    (either: exit status 0 all checked
//!                                    agree, 1 one differs, 2 an error,
//!                                    3 none checkable)
//! binbun why FILE FUNCTION [VAR] [--view exact|reading] [--project DIR]
//! binbun why FILE --all [--view exact|reading]
//!                                    why the function has its name (a
//!                                    library signature's, with the
//!                                    project in DIR) and variables their
//!                                    types and names
//!                                    ([`binbun::queries::evidence`])
//! binbun why FILE --global TARGET    a global's one type over the program
//!                                    with every function's evidence and
//!                                    each field's references
//!                                    ([`binbun::Database::global_type`])
//! binbun origin FILE FUNCTION VAR [--view exact|reading] [--depth N] [--steps N]
//! binbun origin FILE --sample N [--seed S] [--view exact|reading]
//!                                    where a value comes from and goes
//!                                    ([`binbun::queries::origin`])
//! binbun stages FILE FUNCTION [--view exact|reading] [--stage NAME] [--diff]
//!               [--types fixed|plain] [--declarations scoped|top]
//!               [--names numbered|registers] [--profile NAME|PATH]
//!                                    one function through every stage of
//!                                    decompilation ([`binbun::stages`]):
//!                                    the stages, one's text, or its diff;
//!                                    with a profile, its rule at each site
//! binbun sig make --library NAME --version V --licence SPDX INPUT... -o PACK.jsonl.zst
//!                                    a signature pack of a static
//!                                    library's (an archive's, objects',
//!                                    a linked file's) functions,
//!                                    zstd-compressed (`--plain`: JSON
//!                                    Lines, PACK.jsonl)
//!                                    ([`binbun::signatures`])
//! binbun sig check|show|compare PACK...
//!                                    a pack checked, shown, or two
//!                                    compared by identity and bytes
//! binbun sig match FILE --pack PACK... [--behaviour] [--answers UNSTRIPPED]
//!                                    FILE's functions named from packs:
//!                                    exact identities, and with
//!                                    `--behaviour` the candidates run
//!                                    on their recorded states; scored
//!                                    against UNSTRIPPED's symbols
//! binbun sig eval CASES --packs DIR [--sweep|--no-sweep]
//!                                    the signatures evaluation: each
//!                                    case matched and scored against
//!                                    its answers; precision and recall
//!                                    per case and class against the
//!                                    class's targets (fails if missed)
//! binbun id [--name NAME]            this install's identity: key,
//!                                    fingerprint, identity card
//! binbun share FILE [--lan-only] [--relay binbun|n0|none|URL] [--bind IP] [--mdns] [--no-portmap]
//!              [--add CARD]... [--role editor|viewer|agent] [--yes]
//!              [--share ID | --private] [--name NAME] [--ticket-file PATH]
//!              [--send-binary] [--send-debug] [--history list|none|N,...]
//!                                    FILE's project shared in place: a
//!                                    ticket printed; the members added
//!                                    by their cards let in when they
//!                                    join (other ticket holders asked
//!                                    about, or with --yes admitted);
//!                                    commands read on standard input
//!                                    (`collab`); the binary (its debug
//!                                    file) sent, sealed, to members who
//!                                    ask
//! binbun join TICKET [FILE] [--relay binbun|n0|none|URL] [--bind IP] [--mdns] [--no-portmap]
//!             [--name NAME]
//!                                    the project shared by TICKET joined
//!                                    with FILE (the same bytes), fetched
//!                                    from the host first (into binbun's
//!                                    downloads folder without FILE) if
//!                                    it is not there, in a project of
//!                                    its own for the share
//! binbun edit FILE [--share ID | --private] COMMAND...
//!                                    one command on FILE's project,
//!                                    synced at the next share or join
//! binbun bring FILE [--share ID] [--list | --all [--others] | N...] [--label TEXT]
//!                                    values of FILE's private project
//!                                    brought into a share's project as
//!                                    one new change of yours: listed,
//!                                    all of yours (and others' with
//!                                    --others), or those numbered
//! binbun mcp [FILE] [--python PYTHON] [--socket PATH] [--database PATH]
//!                                    binbun's tools for an agent: an MCP
//!                                    server on standard input and output
//!                                    (`python`, `api`) working in the
//!                                    binbun window running, or on FILE
//!                                    without one
//! binbun update --check              this version against the latest
//!                                    release (exit 0 up to date, 1 newer
//!                                    out, 2 no answer)
//! binbun paths [NAME] [--json]       binbun's folders (config, data,
//!                                    state, cache, runtime) with their
//!                                    sizes, or folder NAME's path alone
//! binbun --help                      the usage and binbun's files
//! binbun --version                   `binbun X.Y.Z`
//! ```
//!
//! `decompile`, `eval types` and the whole-program forms of `verify`,
//! `why` and `origin` decompile a whole program's functions on
//! as many threads as the process may run at once, or `BINBUN_THREADS`
//! (1: one thread); the output is the same whatever the threads.
//!
//! `--arch ARCH`, anywhere after the command, opens that slice of a
//! universal Mach-O `FILE` (`x86_64`, `x86_64h`, `arm64`, `arm64e`);
//! without it, the slice for this machine's instruction set, else the
//! first ([`binbun_loader::select`]), said on standard error. Other files
//! are opened whole whatever it says.
//!
//! `--debug PATH` is debug information: a separate ELF debug file, a PDB
//! (checked against the image's GUID and age), a dSYM bundle or its DWARF
//! file (checked against the image's UUID), or `FILE` itself (its own
//! DWARF sections). `decompile` takes it as evidence
//! ([`binbun::debug`]); `eval types` only as the reference it scores against
//! (the decompiler runs without it, [`crate::score::score`]).
//! Without `--debug`, `decompile` and `functions` take a PE image's PDB
//! where debuggers look for it, if it is the image's (GUID and age): at the
//! path the image's `CodeView` record states, then by that file name and
//! by the image's own name beside it ([`binbun_debuginfo::info::locate::Search`]),
//! saying which on standard error (and which files were passed over);
//! `--debug none` takes none.
//!
//! `--symbols` (`--symbols=always`) lets `decompile` fetch the binary's
//! debug information from a symbol server when no local store has it
//! ([`binbun_debuginfo::symbols`]: a PE image's PDB from Microsoft's server or
//! `_NT_SYMBOL_PATH`'s, an ELF image's debug file from the debuginfod
//! servers of `DEBUGINFOD_URLS`), cached in symstore layout under
//! binbun's cache ([`binbun_debuginfo::symbols::config::cache`]), and take it as
//! `--debug` does. A request tells the server which binary is analysed,
//! so nothing is fetched, or looked up, without it (`--symbols=never`,
//! the default).
//!
//! `update --check` is the only command that asks binbun.org anything,
//! and only when run ([`crate::update::command`]): it fetches
//! `https://binbun.org/latest.json` (`BINBUN_UPDATE_URL` replaces it),
//! sending nothing but the request and `User-Agent: binbun/<version>`.
//!
//! `--help` adds where binbun keeps its files ([`FILES`]): the GUI's
//! settings and recent files, the projects (each binary's edits, keyed
//! by its contents), and the symbol cache.
//!
//! `id`, `share`, `join`, `edit` and `bring` are the `collab` feature's
//! (on by default); a binbun built without it says so.
//! `mcp` is the `mcp` feature's (on by default), likewise.

#[cfg(feature = "collab")]
mod collab;
mod facts;
mod graph;
#[cfg(feature = "mcp")]
mod mcp;
mod paths;
mod run;
mod sig;
mod stages;
mod xrefs;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;
use std::sync::OnceLock;
use std::time::Instant;

use binbun::analysis::{Seeds, names, x86_mode};
use binbun::cfg::{BlockId, Destination, Exit, Program, Returns};
use binbun::debug::DebugInfo;
use binbun::decompile::{self, Output, Stats};
use binbun::eval::{evaluate, lifting};
use binbun::{Database, Error};
use binbun_aarch64::decode_bytes;
use binbun_debuginfo::info::DebugModel;
use binbun_debuginfo::info::locate::Search;
use binbun_debuginfo::symbols::{Cancel, Config as SymbolConfig, Identity};
use binbun_decompile::lower::DebugCounts;
use binbun_decompile::typing::Kind;
use binbun_loader::{Clause, Format, Image, Machine, Referent, TypeInfo};
use binbun_paths::{Dir, Platform};
use binbun_print::c::{HEADER, Unknowns};
use binbun_print::style::{IntSpelling, Naming, Placement, Style};
use binbun_semantics::core::Memory;
use binbun_x86::decode;

use crate::provenance::{Coverage, coverage};
use crate::{Verdict, compile_check, score, update};

const USAGE: &str = "usage:
  binbun [FILE]                      the GUI (FILE open in it)
  binbun functions FILE
  binbun cfg FILE FUNCTION [--dot]
  binbun graph FILE FUNCTION [--svg OUT]
  binbun eval [--seeds entry|all] [--no-pointers] FILE...
  binbun eval types FILE [--debug PATH] [--totals]
  binbun decompile FILE [FUNCTION...] [--style PRESET] [--l2] [--stats]
                   [--disable-pass NAME]... [--debug PATH]
                   [--view exact|reading] [--symbols[=always|never]]
                   [--types fixed|plain] [--declarations scoped|top]
                   [--names numbered|registers]
  binbun strings FILE [--min N] [--referenced]
  binbun xrefs FILE TARGET
  binbun xrefs FILE --from FUNCTION
  binbun run FILE FUNCTION --state STATE.toml [--view exact|reading]
             [--types fixed|plain] [--declarations scoped|top]
             [--names numbered|registers] [--depth N] [--steps N]
             [--profile NAME|PATH]
  binbun verify FILE [FUNCTION] [--view exact|reading] [--states N] [--shaped N]
                [--seed N] [--fuel N] [--project DIR] [--profile NAME|PATH]
  binbun verify FILE [FUNCTION] --compare PROFILE,PROFILE... [--states N] [--shaped N]
                [--seed N] [--fuel N] [--save DIR] [--states-full]
  binbun why FILE FUNCTION [VAR] [--view exact|reading] [--project DIR]
  binbun why FILE --all [--view exact|reading]
  binbun why FILE --global TARGET
  binbun origin FILE FUNCTION VAR [--view exact|reading] [--depth N] [--steps N]
  binbun origin FILE --sample N [--seed S] [--view exact|reading]
  binbun stages FILE FUNCTION [--view exact|reading] [--stage NAME] [--diff]
                [--types fixed|plain] [--declarations scoped|top]
                [--names numbered|registers] [--profile NAME|PATH]
  binbun sig make --library NAME --version V --licence SPDX [--build ID] [--toolchain T]
                  [--flags F] [--code] [--no-separators] [--add-to PACK] INPUT...
                  -o PACK.jsonl.zst [--plain: -o PACK.jsonl]
  binbun sig check PACK
  binbun sig show PACK [NAME]
  binbun sig compare PACK PACK
  binbun sig match FILE --pack PACK... [--behaviour] [--answers UNSTRIPPED]
  binbun sig eval CASES --packs DIR [--sweep|--no-sweep]
  binbun id [--name NAME]
  binbun share FILE [--lan-only] [--relay binbun|n0|none|URL] [--bind IP] [--mdns] [--no-portmap]
                    [--add CARD]... [--role editor|viewer|agent] [--yes]
                    [--share ID | --private] [--name NAME] [--ticket-file PATH]
                    [--send-binary] [--send-debug] [--history list|none|N,...]
  binbun join TICKET [FILE] [--relay binbun|n0|none|URL] [--bind IP] [--mdns] [--no-portmap]
              [--name NAME]
  binbun edit FILE [--share ID | --private] COMMAND...
  binbun bring FILE [--share ID] [--list | --all [--others] | N...] [--label TEXT]
  binbun mcp [FILE] [--python PYTHON] [--socket PATH] [--database PATH]
  binbun update --check
  binbun paths [config|data|state|cache|runtime] [--json]
  binbun --help
  binbun --version

  --arch ARCH (any command): the slice of a universal Mach-O FILE to open

verify exits 0 when all it checked agrees (some functions may be not checkable),
  1 when a function differs (with --compare: between the processors), 2 when it
  fails (a file, a function or an argument wrong), 3 when nothing was checkable";

/// Where binbun keeps its files, for `--help` ([`binbun_paths`]): each
/// folder's place on this platform.
fn files() -> String {
    let mut text = "folders (each under BINBUN_HOME if set, else under its XDG variable if set;\n\
                    `binbun paths` lists them with their sizes):"
        .to_owned();
    for dir in Dir::ALL {
        let _ = write!(text, "\n  {:<8} ", dir.name());
        match dir.shown(Platform::CURRENT) {
            Some(shown) => text.push_str(&shown),
            None => {
                let _ = write!(text, "${}/binbun", dir.variable());
            }
        }
    }
    text
}

/// The most functions `eval` builds in L1 per file: building every
/// function of a large binary takes longer than recovering it (node.exe's
/// 89,361 take 17 s), so beyond this a deterministic sample is built.
const L1_SAMPLE: usize = 5000;

/// `--arch`: the slice of a universal Mach-O file every command opens.
static ARCH: OnceLock<Option<String>> = OnceLock::new();

/// The slice `--arch` asks for, if it does.
fn arch() -> Option<&'static str> {
    ARCH.get().and_then(Option::as_deref)
}

/// Takes `--arch ARCH` (or `--arch=ARCH`) out of `args`: its value, if
/// given.
fn take_arch(args: &mut Vec<String>) -> Result<Option<String>, String> {
    let Some(at) = args
        .iter()
        .position(|arg| arg == "--arch" || arg.starts_with("--arch="))
    else {
        return Ok(None);
    };
    let flag = args.remove(at);
    if let Some(value) = flag.strip_prefix("--arch=") {
        return Ok(Some(value.to_owned()));
    }
    if at < args.len() {
        Ok(Some(args.remove(at)))
    } else {
        Err("--arch needs an architecture (x86_64, arm64e, ...)".to_owned())
    }
}

/// The words that name a command (the first argument): anything else
/// given alone is a file for the GUI ([`crate::Invocation`]).
pub(crate) const COMMANDS: [&str; 26] = [
    "functions",
    "cfg",
    "graph",
    "eval",
    "decompile",
    "strings",
    "xrefs",
    "run",
    "verify",
    "why",
    "origin",
    "stages",
    "sig",
    "id",
    "share",
    "join",
    "edit",
    "bring",
    "mcp",
    "update",
    "paths",
    "help",
    "--help",
    "-h",
    "--version",
    "-V",
];

/// Runs the command `args` (`[command, arguments...]`): its output on
/// standard output, or what went wrong (the usage, for no command) on
/// standard error. `gui` says whether this binbun has the GUI, for
/// `--help`.
pub(crate) fn command(args: &[String], gui: bool) -> ExitCode {
    let mut args = args.to_vec();
    match take_arch(&mut args) {
        Ok(arch) => {
            let _ = ARCH.set(arch);
        }
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    }
    let args = args.as_slice();
    let (command, rest) = args
        .split_first()
        .map_or(("", &[][..]), |(c, r)| (c.as_str(), r));
    if command == "update" {
        return update::command::command(rest);
    }
    if command == "verify" {
        return match facts::verify(rest) {
            Ok((text, status)) => {
                print!("{text}");
                ExitCode::from(status)
            }
            Err(message) => {
                eprintln!("{message}");
                ExitCode::from(facts::FAILED)
            }
        };
    }
    let result = match command {
        "functions" => functions(rest),
        "cfg" => cfg(rest),
        "graph" => graph::graph(rest),
        "eval" => eval(rest),
        "decompile" => decompile(rest),
        "strings" => xrefs::strings(rest),
        "xrefs" => xrefs::xrefs(rest),
        "run" => run::run(rest),
        "why" => facts::why(rest),
        "origin" => facts::origin(rest),
        "stages" => stages::stages_command(rest),
        "sig" => sig::sig(rest),
        "paths" => paths::paths(rest),
        #[cfg(feature = "collab")]
        "id" => collab::id(rest),
        #[cfg(feature = "collab")]
        "share" => collab::share(rest),
        #[cfg(feature = "collab")]
        "join" => collab::join(rest),
        #[cfg(feature = "collab")]
        "edit" => collab::edit(rest),
        #[cfg(feature = "collab")]
        "bring" => collab::bring(rest),
        #[cfg(not(feature = "collab"))]
        "id" | "share" | "join" | "edit" | "bring" => Err(format!(
            "binbun {command}: this binbun was built without collaboration (the `collab` feature)"
        )),
        #[cfg(feature = "mcp")]
        "mcp" => mcp::mcp(rest),
        #[cfg(not(feature = "mcp"))]
        "mcp" => Err(
            "binbun mcp: this binbun was built without the MCP server (the `mcp` feature)"
                .to_owned(),
        ),
        "--help" | "-h" | "help" => Ok(format!(
            "{USAGE}\n\n{}{}\n",
            if gui { "" } else { WITHOUT_GUI_NOTE },
            files()
        )),
        "--version" | "-V" => Ok(format!("binbun {}\n", env!("CARGO_PKG_VERSION"))),
        _ if command.starts_with('-') => {
            eprintln!("binbun: unknown option {command}\n\n{USAGE}");
            return ExitCode::from(MISUSED);
        }
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// The exit status of a flag that is no command's (the usual one of a
/// command misused).
const MISUSED: u8 = 2;

/// What `--help` says of a binbun built without the GUI.
const WITHOUT_GUI_NOTE: &str =
    "this binbun was built without the GUI: `binbun [FILE]` needs the GUI's build\n\n";

/// A binbun built without the GUI, asked for it (no command, or `file`
/// alone): says so, and gives the usage.
pub(crate) fn without_gui(file: Option<&Path>) -> ExitCode {
    let said = match file {
        Some(file) => format!(
            "{} is no command, and this binbun was built without the GUI (which opens a file given alone)",
            file.display()
        ),
        None => "this binbun was built without the GUI: give it a command".to_owned(),
    };
    eprintln!("binbun: {said}\n\n{USAGE}");
    ExitCode::FAILURE
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn load<'a>(path: &str, data: &'a [u8]) -> Result<Image<'a>, String> {
    let image = Image::parse_arch(data, arch()).map_err(|e| format!("{path}: {e}"))?;
    if let Some(slice) = &image.slice {
        let all: Vec<String> = binbun_loader::slices(data)
            .unwrap_or_default()
            .into_iter()
            .map(|slice| slice.arch)
            .collect();
        eprintln!(
            "{path}: the {} slice of a universal file ({}; --arch chooses)",
            slice.arch,
            all.join(", ")
        );
    }
    Ok(image)
}

/// The bytes of the image in `data` that `--arch` opens: one slice of a
/// universal Mach-O file, else all.
fn image_bytes(data: &[u8]) -> &[u8] {
    binbun_loader::select(data, arch()).map_or(data, |(bytes, _)| bytes)
}

fn database<'a>(path: &str, image: &'a Image<'a>, seeds: Seeds) -> Result<Database<'a>, String> {
    database_with(path, image, seeds, None)
}

/// [`database`] with debug information `debug` as evidence.
fn database_with<'a>(
    path: &str,
    image: &'a Image<'a>,
    seeds: Seeds,
    debug: Option<DebugModel>,
) -> Result<Database<'a>, String> {
    Database::with_debug(image, seeds, debug).map_err(|error| match error {
        Error::Library(_) => error.to_string(),
        Error::Unsupported(_) => format!("{path}: {error}"),
    })
}

/// The debug information at `debug` for the image `data` (a separate ELF
/// debug file, a PDB, a dSYM bundle or file, or the image itself where
/// `debug` is its path).
fn debug_model(debug: &str, path: &str, data: &[u8]) -> Result<DebugModel, String> {
    binbun_debuginfo::info::locate::open(Path::new(debug), Path::new(path), image_bytes(data))
}

/// A PE image's PDB where debuggers look for it: at the path its
/// `CodeView` record states (if it exists here), then by that name, then
/// by the image's own, beside it ([`binbun_debuginfo::info::locate::Search`]), if
/// its GUID and age are the image's; said on standard error, as is each
/// file passed over (another build's). Other formats' debug files are
/// taken only from `--debug` (their conventional places hold the
/// system's, which `--debug` names when wanted).
fn beside(path: &str, data: &[u8], image: &Image<'_>) -> Option<DebugModel> {
    if image.format != Format::Pe {
        return None;
    }
    let searched = Search::from_environment().search(Path::new(path), image_bytes(data));
    for (file, reason) in &searched.passed {
        eprintln!("{}: not used: {reason}", file.display());
    }
    let found = searched.found?;
    eprintln!("{path}: debug information from {}", found.path.display());
    Some(found.model)
}

/// `--symbols`: the debug information of the image `data` (at `path`)
/// from a local symbol store, else fetched from a symbol server
/// ([`binbun_debuginfo::symbols::Config::from_environment`]); what happened is said
/// on standard error, and the image is decompiled without where nothing
/// is found.
fn symbols(path: &str, data: &[u8]) -> Option<DebugModel> {
    let data = image_bytes(data);
    let Some(identity) = Identity::of(data) else {
        eprintln!("{path}: no symbol server serves this format's debug information");
        return None;
    };
    let config = SymbolConfig::from_environment();
    let file = match config.locate(&identity) {
        Some(file) => file,
        None => match config.fetch(&identity, &Cancel::default()) {
            Ok(fetched) => {
                eprintln!(
                    "{path}: fetched {identity} from {} to {}",
                    fetched.server.host(),
                    fetched.path.display()
                );
                fetched.path
            }
            Err(failure) => {
                eprintln!("{path}: {identity}: {failure}");
                return None;
            }
        },
    };
    match std::fs::read(&file)
        .map_err(|error| error.to_string())
        .and_then(|debug| binbun_debuginfo::info::read(&debug, data))
    {
        Ok(model) => Some(model),
        Err(error) => {
            eprintln!("{}: {error}", file.display());
            None
        }
    }
}

fn functions(args: &[String]) -> Result<String, String> {
    let [path] = args else {
        return Err(USAGE.to_owned());
    };
    let data = read(path)?;
    let image = load(path, &data)?;
    let debug = beside(path, &data, &image);
    let database = database_with(path, &image, Seeds::ALL, debug)?;
    let mut out = String::new();
    for (_, function) in database.functions() {
        let name = database.name(function.entry).unwrap_or("");
        let returns = if function.returns { "" } else { " noreturn" };
        write!(
            out,
            "{:#x} {:>5} blocks{returns} {name}",
            function.entry,
            function.blocks.len()
        )
        .map_err(|e| e.to_string())?;
        for part in &function.parts {
            write!(out, " +part {part:#x}").map_err(|e| e.to_string())?;
        }
        for funclet in &function.funclets {
            write!(out, " +funclet {funclet:#x}").map_err(|e| e.to_string())?;
        }
        if let Some(owner) = function.part_of {
            write!(out, " (part of {owner:#x})").map_err(|e| e.to_string())?;
        }
        out.push('\n');
    }
    Ok(out)
}

fn cfg(args: &[String]) -> Result<String, String> {
    let (dot, args): (bool, Vec<&String>) = (
        args.iter().any(|a| a == "--dot"),
        args.iter().filter(|a| *a != "--dot").collect(),
    );
    let [path, wanted] = args[..] else {
        return Err(USAGE.to_owned());
    };
    let data = read(path)?;
    let image = load(path, &data)?;
    let database = database(path, &image, Seeds::ALL)?;
    let program = database.program();
    let id = database.find_function(wanted)?;
    let function = database
        .function(id)
        .ok_or_else(|| format!("no function {wanted}"))?;
    let entry = function.entry;
    let name = |address: u64| {
        database
            .name(address)
            .map_or_else(|| format!("{address:#x}"), str::to_owned)
    };
    let import = |slot: u64| {
        image
            .imports
            .iter()
            .find(|i| i.slot == slot)
            .map_or_else(|| format!("[{slot:#x}]"), |i| i.name.clone())
    };
    let mut out = String::new();
    let w = |out: &mut String, text: String| out.push_str(&text);
    if dot {
        w(
            &mut out,
            format!(
                "digraph \"{}\" {{\n  node [shape=box fontname=monospace];\n",
                name(entry)
            ),
        );
    }
    for &id in &function.blocks {
        let Some(block) = program.blocks.get(id) else {
            continue;
        };
        let text = disassemble(&image, program, id);
        if dot {
            let label = text
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\l");
            w(
                &mut out,
                format!("  b{:x} [label=\"{label}\"];\n", block.start),
            );
            for (kind, target) in program.successors(id) {
                if function
                    .blocks
                    .iter()
                    .any(|&b| program.blocks.get(b).is_some_and(|b| b.start == target))
                {
                    w(
                        &mut out,
                        format!(
                            "  b{:x} -> b{target:x} [label=\"{kind:?}\"];\n",
                            block.start
                        ),
                    );
                }
            }
        } else {
            w(&mut out, format!("{:#x}:\n{text}", block.start));
            w(
                &mut out,
                format!("  -> {}\n", exit(&block.exit, &name, &import)),
            );
        }
    }
    if dot {
        w(&mut out, "}\n".to_owned());
    } else {
        let starts: Vec<u64> = function
            .blocks
            .iter()
            .filter_map(|&b| program.blocks.get(b).map(|b| b.start))
            .collect();
        exception_tables(&mut out, &image, &starts).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Writes the exception tables of the parts of a function starting at
/// `starts` (its blocks) to `out`: per call site its range, landing pad and
/// clauses.
fn exception_tables(out: &mut String, image: &Image<'_>, starts: &[u64]) -> std::fmt::Result {
    let named = |referent: &Referent| {
        referent.symbol.clone().unwrap_or_else(|| {
            referent
                .address
                .or(referent.slot)
                .map_or_else(|| "?".to_owned(), |address| format!("{address:#x}"))
        })
    };
    let type_name = |t: &TypeInfo| t.name.clone().unwrap_or_else(|| named(&t.object));
    for table in &image.exception_tables {
        if !starts.contains(&table.function) {
            continue;
        }
        let personality = table
            .personality
            .as_ref()
            .map_or_else(|| "none".to_owned(), named);
        writeln!(
            out,
            "exception table {:#x} of {:#x}, personality {personality}:",
            table.lsda, table.function
        )?;
        for call_site in &table.call_sites {
            let Some(pad) = call_site.landing_pad else {
                writeln!(
                    out,
                    "  {:#x}..{:#x} unwinds",
                    call_site.start, call_site.end
                )?;
                continue;
            };
            let clauses: Vec<String> = call_site
                .clauses
                .iter()
                .zip(&call_site.selectors)
                .map(|(clause, selector)| {
                    let clause = match clause {
                        Clause::Catch(t) => format!("catch {}", type_name(t)),
                        Clause::CatchAll => "catch ...".to_owned(),
                        Clause::Cleanup => "cleanup".to_owned(),
                        Clause::Filter(types) => {
                            let types: Vec<String> = types.iter().map(type_name).collect();
                            format!("throw({})", types.join(", "))
                        }
                    };
                    format!("{clause} [{selector}]")
                })
                .collect();
            writeln!(
                out,
                "  {:#x}..{:#x} -> {pad:#x}: {}",
                call_site.start,
                call_site.end,
                clauses.join(", ")
            )?;
        }
    }
    Ok(())
}

/// A block's instructions (x86 in Intel syntax), one per line.
fn disassemble(image: &Image<'_>, program: &Program, id: BlockId) -> String {
    let mut out = String::new();
    let Some(block) = program.blocks.get(id) else {
        return out;
    };
    let mut pc = block.start;
    while pc < block.end {
        let mut bytes = [0u8; 15];
        let read = image.read(pc, &mut bytes).unwrap_or(0);
        let bytes = bytes.get(..read).unwrap_or_default();
        let length = if image.machine == Machine::Aarch64 {
            let Ok(instruction) = decode_bytes(bytes) else {
                break;
            };
            let _ = writeln!(out, "  {pc:x}  {}", instruction.display(pc));
            4
        } else {
            let Ok(mode) = x86_mode(image.machine) else {
                break;
            };
            let Ok(instruction) = decode(bytes, mode) else {
                break;
            };
            let _ = writeln!(out, "  {pc:x}  {}", instruction.intel(pc));
            instruction.len() as u64
        };
        pc += length;
    }
    out
}

fn exit(exit: &Exit, name: &dyn Fn(u64) -> String, import: &dyn Fn(u64) -> String) -> String {
    let destination = |d: &Destination| match *d {
        Destination::Address(address) => name(address),
        Destination::Import(slot) => format!("import {}", import(slot)),
        Destination::Pointer(slot) => format!("[{slot:#x}] (unresolved)"),
        Destination::Indirect => "indirect (unresolved)".to_owned(),
        Destination::Far => "far (unresolved)".to_owned(),
    };
    match exit {
        Exit::Next => "next".to_owned(),
        Exit::Jump(d) => format!("jump {}", destination(d)),
        Exit::Branch(d) => format!("branch {} or next", destination(d)),
        Exit::Call { callee, returns } => {
            let after = match returns {
                Returns::Yes => "then next",
                Returns::No => "noreturn",
                Returns::Unknown => "then next (assumed)",
            };
            format!("call {}, {after}", destination(callee))
        }
        Exit::Return => "return".to_owned(),
        Exit::Stop => "stop".to_owned(),
        Exit::Invalid => "invalid code".to_owned(),
        Exit::Limit => "block too long".to_owned(),
    }
}

fn eval(args: &[String]) -> Result<String, String> {
    if let Some((first, rest)) = args.split_first()
        && first == "types"
    {
        return eval_types(rest);
    }
    let mut seeds = Seeds::ALL;
    let mut paths = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--seeds" {
            seeds.stated = match args.next().map(String::as_str) {
                Some("entry") => false,
                Some("all") => true,
                _ => return Err(USAGE.to_owned()),
            };
        } else if arg == "--no-pointers" {
            seeds.pointers = false;
        } else {
            paths.push(arg);
        }
    }
    let mut out = format!(
        "| File | Functions stated | Found | Recall | Precision | Instructions | Coverage | Non-returning | Unresolved jumps / calls | Tables (inferred) | Conflicts | Overlaps / missing targets (should be 0) | Load ms | Recover ms | Lifted | L1 (at most {L1_SAMPLE} functions, evenly by address) | Thunks |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
    );
    for path in paths {
        let data = read(path)?;
        let started = Instant::now();
        let image = load(path, &data)?;
        let loaded = started.elapsed();
        let started = Instant::now();
        let database = database(path, &image, seeds)?;
        let recovered = started.elapsed();
        let e = evaluate(&image, database.program());
        let (lifted, l1) = lifting(&image, database.program(), L1_SAMPLE).map_or_else(
            || ("-".to_owned(), "-".to_owned()),
            |l| {
                (
                    format!("{:.1}%", l.lifted() * 100.0),
                    format!("{:.1}%", l.l1() * 100.0),
                )
            },
        );
        let name = path.rsplit('/').next().unwrap_or(path);
        #[expect(clippy::cast_precision_loss, reason = "byte counts are far below 2^52")]
        let coverage = e.covered as f64 / e.code.max(1) as f64;
        let _ = writeln!(
            out,
            "| {name} | {} | {} | {:.1}% | {:.1}% | {} | {:.1}% | {} | {} / {} | {} ({}) | {} | {} / {} | {} | {} | {lifted} | {l1} | {} |",
            e.truth,
            e.found,
            e.recall() * 100.0,
            e.precision() * 100.0,
            e.instructions,
            coverage * 100.0,
            e.non_returning,
            e.unresolved_jumps,
            e.unresolved_calls,
            e.tables,
            e.inferred_tables,
            e.conflicts,
            e.unexplained_overlaps,
            e.missing_targets,
            loaded.as_millis(),
            recovered.as_millis(),
            e.thunks,
        );
    }
    Ok(out)
}

/// `eval types`: the decompiler's types for `FILE` (decompiled as it is)
/// scored against the debug information in `--debug PATH` (a separate ELF
/// debug file or a PDB), else in `FILE` itself; `--totals` prints the
/// totals only (held-out binaries).
fn eval_types(args: &[String]) -> Result<String, String> {
    let mut path = None;
    let mut debug = None;
    let mut totals = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--debug" => debug = Some(args.next().ok_or_else(|| USAGE.to_owned())?),
            "--totals" => totals = true,
            _ if arg.starts_with("--") || path.is_some() => return Err(USAGE.to_owned()),
            _ => path = Some(arg),
        }
    }
    let path = path.ok_or_else(|| USAGE.to_owned())?;
    let data = read(path)?;
    let model = debug_model(debug.map_or(path.as_str(), String::as_str), path, &data)?;
    let image = load(path, &data)?;
    // The decompiler runs without the debug information it is scored
    // against (`score` refuses a database that has some).
    let database = database(path, &image, Seeds::ALL)?;
    let setup = score::Setup::new(&database);
    let report = score::score(&database, &model, &setup)?;
    Ok(if totals {
        format!("{}\n", report.totals())
    } else {
        report.to_string()
    })
}

/// `decompile FILE [FUNCTION...] [--style PRESET] [--l2] [--stats]
/// [--disable-pass NAME]... [--debug PATH] [--view exact|reading]
/// [--types fixed|plain] [--declarations scoped|top]
/// [--names numbered|registers]`: the
/// functions named (by name or address; each printed as it is asked for
/// alone, in the order asked, the file read once), or every function, as
/// C (or L2's text), without the passes
/// named (to see what each does), with the debug information at `PATH`
/// as evidence, exact (the default) or as the reading view
/// ([`decompile::View::Reading`], said in a first comment), its integer
/// types fixed-width (the default) or C's own names for the image's data
/// model ([`IntSpelling::Plain`]), its locals declared in the blocks
/// using them (`scoped`, the default) or all at the top of each function
/// (`top`), its variables with no name of their own named by kind and
/// number (`numbered`, the default: `a1`, `v7`) or by where the machine
/// code kept them (`registers`: `arg1`, `rax`, `var_58`). With
/// `--stats`, a comment before each function counts
/// its gotos, escapes and casts, compiles it, and gives each pass's runs,
/// changes and refusals, how often each analysis was computed and how
/// much of its machine code its lines came from
/// ([`binbun_cli::provenance`]; totalled in a last comment). A
/// function that cannot be decompiled is a comment saying why; asked for
/// by name or address, an error. Every function: decompiled, printed and
/// compiled on [`decompile::threads`] threads
/// ([`Database::decompile_all`]); with
/// `--stats` and `--debug`, a last comment totals what became of the
/// debug information. With `--symbols`, the debug information found in a
/// local symbol store or fetched from a symbol server ([`symbols`]) when
/// no `--debug` is given.
fn decompile(args: &[String]) -> Result<String, String> {
    let (flags, path, wanted) = decompile_arguments(args)?;
    let data = read(path)?;
    let image = load(path, &data)?;
    let debug = match flags.debug.as_deref() {
        Some("none") => None,
        Some(debug) => Some(debug_model(debug, path, &data)?),
        None => beside(path, &data, &image).or_else(|| {
            if flags.symbols {
                symbols(path, &data)
            } else {
                None
            }
        }),
    };
    let database = database_with(path, &image, Seeds::ALL, debug)?;
    let options = decompile::Options {
        style: (!flags.l2).then(|| flags.style.clone()),
        disabled: flags.disabled.clone(),
        view: flags.view,
        types: flags.types,
        declarations: flags.declarations,
        names: flags.names,
    };
    let reading = if flags.view == decompile::View::Reading {
        format!(
            "/* Reading view: assumes {}; the checks this settles and their traps are not shown (exact C: --view exact). */\n\n",
            decompile::View::ASSUMPTIONS
        )
    } else {
        String::new()
    };
    if !wanted.is_empty() {
        let mut text = String::new();
        for function in wanted {
            let id = database.find_function(function)?;
            let output = rendered(&database, database.decompile(id, &options), &flags);
            if let Err(message) = &output.result {
                return Err(format!("{function}: {message}"));
            }
            text.push_str(&reading);
            text.push_str(&render(std::slice::from_ref(&output), flags.stats));
        }
        return Ok(text);
    }
    let mut outputs = Vec::new();
    database.decompile_all(
        &options,
        |output| rendered(&database, output, &flags),
        |output| outputs.push(output),
    );
    outputs.sort_by_key(|output| output.entry);
    let mut text = reading;
    text.push_str(&render(&outputs, flags.stats));
    if flags.stats {
        text.push_str(&class_totals(&database, &options.disabled, &outputs));
        text.push_str(&global_totals(&database, &options.disabled));
        text.push_str(&provenance_totals(&outputs));
    }
    if flags.stats
        && let Some(debug) = database.debug()
    {
        text.push_str(&debug_totals(&database, debug, &outputs));
    }
    Ok(text)
}

/// What the C++ classes of the image (`binbun::classes`) named over
/// `outputs` (the passes `disabled`), as a comment: classes, primary
/// virtual tables, methods, structs named by a class (classes and their
/// virtual tables), and the functions whose C reads a `vptr` field (a
/// virtual call's table; not a constructor's store), with how many such
/// reads.
fn class_totals(database: &Database<'_>, disabled: &[String], outputs: &[Rendered]) -> String {
    let callers = database.callers(disabled);
    let structs = callers.schemes.structs();
    let classes = structs.classes();
    let reads: Vec<usize> = outputs
        .iter()
        .filter_map(|output| output.result.as_ref().ok())
        .map(|(text, _)| {
            text.match_indices("->vptr")
                .filter(|&(at, found)| {
                    text.get(at + found.len()..)
                        .is_some_and(|rest| !rest.starts_with(" = "))
                })
                .count()
        })
        .filter(|&count| count > 0)
        .collect();
    format!(
        "/* classes {}, vtables {}, methods {}, structs named by class {}, functions reading a vptr {} ({} reads) */\n",
        classes.len(),
        classes.vtables(),
        classes.methods(),
        structs.classed(),
        reads.len(),
        reads.iter().sum::<usize>(),
    )
}

/// The program's global types (`binbun_decompile::typing::Globals`, the
/// passes `disabled`) by kind, as a comment: one type per global over the
/// whole program, with the evidence of other types they override.
fn global_totals(database: &Database<'_>, disabled: &[String]) -> String {
    let callers = database.callers(disabled);
    let globals = callers.schemes.globals();
    let kinds = globals.kinds();
    let count = |kind: Kind| kinds.get(&kind).copied().unwrap_or(0);
    let conflicts: usize = globals.iter().map(|(_, ty)| ty.conflicts).sum();
    format!(
        "/* globals typed {}: declared {}, scalar {}, pointer {}, array {}, struct {}; evidence overridden {} */\n",
        globals.len(),
        count(Kind::Declared),
        count(Kind::Scalar),
        count(Kind::Pointer),
        count(Kind::Array),
        count(Kind::Struct),
        conflicts,
    )
}

/// How much of their machine code the C of `outputs` says it came from
/// ([`coverage`]), as a comment: the functions with an instruction
/// counted, the share of all their counted instructions some line came
/// from, the mean of each function's share and its low tail (the 1st,
/// 5th, 10th and 25th percentiles, the functions under 90% and 50%),
/// and the unmapped instructions' commonest mnemonics.
fn provenance_totals(outputs: &[Rendered]) -> String {
    let all: Vec<&Coverage> = outputs
        .iter()
        .filter_map(|output| output.coverage.as_ref())
        .filter(|coverage| coverage.counted > 0)
        .collect();
    let mut shares: Vec<f64> = all.iter().filter_map(|c| c.share()).collect();
    shares.sort_by(f64::total_cmp);
    let (covered, counted, excluded) = all.iter().fold((0, 0, 0), |(a, b, c), coverage| {
        (
            a + coverage.covered,
            b + coverage.counted,
            c + coverage.excluded,
        )
    });
    let frame: usize = all.iter().map(|coverage| coverage.frame).sum();
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "counts are far below 2^52; a percentile's index is within the list"
    )]
    let percentile = |p: f64| {
        let at = ((shares.len().saturating_sub(1)) as f64 * p).round() as usize;
        shares.get(at).map_or(0.0, |share| share * 100.0)
    };
    #[expect(clippy::cast_precision_loss, reason = "counts are far below 2^52")]
    let (whole, mean) = (
        covered as f64 * 100.0 / counted.max(1) as f64,
        shares.iter().sum::<f64>() * 100.0 / shares.len().max(1) as f64,
    );
    let below = |limit: f64| shares.iter().filter(|&&share| share < limit).count();
    let mut unmapped: BTreeMap<&str, usize> = BTreeMap::new();
    for coverage in &all {
        for (mnemonic, count) in &coverage.unmapped {
            *unmapped.entry(mnemonic).or_default() += count;
        }
    }
    let mut commonest: Vec<(&str, usize)> = unmapped.into_iter().collect();
    commonest.sort_by_key(|&(mnemonic, count)| (core::cmp::Reverse(count), mnemonic));
    let commonest: Vec<String> = commonest
        .iter()
        .take(12)
        .map(|(mnemonic, count)| format!("{mnemonic} {count}"))
        .collect();
    format!(
        "/* provenance: functions {}, instructions {covered}/{counted} on a line ({whole:.1}%; no C {excluded}, frame unmapped {frame}), per function mean {mean:.1}%, p1 {:.1}%, p5 {:.1}%, p10 {:.1}%, p25 {:.1}%, under 90% {}, under 50% {}; unmapped {} */\n",
        shares.len(),
        percentile(0.01),
        percentile(0.05),
        percentile(0.10),
        percentile(0.25),
        below(0.9),
        below(0.5),
        commonest.join(", "),
    )
}

/// `--types`' value `name`: `fixed` or `plain`.
///
/// # Errors
///
/// None given, or another: the usage.
pub(crate) fn int_spelling(name: Option<&String>) -> Result<IntSpelling, String> {
    match name.map(String::as_str) {
        Some("fixed") => Ok(IntSpelling::Fixed),
        Some("plain") => Ok(IntSpelling::Plain),
        _ => Err(USAGE.to_owned()),
    }
}

/// `--declarations`' value: `scoped` or `top`.
///
/// # Errors
///
/// None given, or another: the usage.
pub(crate) fn placement(value: Option<&String>) -> Result<Placement, String> {
    match value.map(String::as_str) {
        Some("scoped") => Ok(Placement::Scoped),
        Some("top") => Ok(Placement::Top),
        _ => Err(USAGE.to_owned()),
    }
}

/// `--names`' value: `numbered` or `registers`.
///
/// # Errors
///
/// None given, or another: the usage.
pub(crate) fn naming(value: Option<&String>) -> Result<Naming, String> {
    match value.map(String::as_str) {
        Some("numbered") => Ok(Naming::Numbered),
        Some("registers") => Ok(Naming::Registers),
        _ => Err(USAGE.to_owned()),
    }
}

/// What `binbun decompile` prints, and how.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Flags {
    /// The name of the style preset the C is laid out in.
    style: String,
    /// Print L2's text form instead of C.
    l2: bool,
    /// Count gotos, escapes and casts, and compile the C.
    stats: bool,
    /// The passes not run, by name ([`decompile::passes`]).
    disabled: Vec<String>,
    /// The debug information to take as evidence, by path.
    debug: Option<String>,
    /// Whether debug information may be fetched from a symbol server.
    symbols: bool,
    /// Exact C, or the reading view.
    view: decompile::View,
    /// How the C spells integer types.
    types: IntSpelling,
    /// Where the C declares locals.
    declarations: Placement,
    /// How the C names variables with no name of their own.
    names: Naming,
}

/// The flags, the file and the functions (none for every one) of
/// `decompile`'s `args`.
fn decompile_arguments(args: &[String]) -> Result<(Flags, &str, Vec<&str>), String> {
    let mut flags = Flags {
        style: "kr".to_owned(),
        l2: false,
        stats: false,
        disabled: Vec::new(),
        debug: None,
        symbols: false,
        view: decompile::View::Exact,
        types: IntSpelling::Fixed,
        declarations: Placement::Scoped,
        names: Naming::Numbered,
    };
    let mut positional = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--style" => {
                flags
                    .style
                    .clone_from(args.next().ok_or_else(|| USAGE.to_owned())?);
            }
            "--l2" => flags.l2 = true,
            "--stats" => flags.stats = true,
            "--debug" => {
                flags.debug = Some(args.next().ok_or_else(|| USAGE.to_owned())?.clone());
            }
            "--symbols" | "--symbols=always" => flags.symbols = true,
            "--symbols=never" => flags.symbols = false,
            "--view" => {
                flags.view = match args.next().map(String::as_str) {
                    Some("exact") => decompile::View::Exact,
                    Some("reading") => decompile::View::Reading,
                    _ => return Err(USAGE.to_owned()),
                };
            }
            "--types" => flags.types = int_spelling(args.next())?,
            "--declarations" => flags.declarations = placement(args.next())?,
            "--names" => flags.names = naming(args.next())?,
            "--disable-pass" => {
                let name = args.next().ok_or_else(|| USAGE.to_owned())?;
                let passes = decompile::passes();
                if !passes.contains(&name.as_str()) {
                    return Err(format!(
                        "no pass {name:?}; the passes are {}",
                        passes.join(", ")
                    ));
                }
                flags.disabled.push(name.clone());
            }
            _ if arg.starts_with("--") => return Err(USAGE.to_owned()),
            _ => positional.push(arg.as_str()),
        }
    }
    match positional.split_first() {
        Some((path, wanted)) => Ok((flags, path, wanted.to_vec())),
        None => Err(USAGE.to_owned()),
    }
}

/// One function's text, or why there is none.
struct Rendered {
    /// The function's entry.
    entry: u64,
    /// Its name, if the image has one.
    name: Option<String>,
    /// Its text (C, or L2's text form) with, under `--stats`, its counts;
    /// or why there is none.
    result: Result<(String, Option<String>), String>,
    /// What became of what debug information states about it.
    debug: DebugCounts,
    /// Under `--stats`, how much of its machine code its C's lines came
    /// from.
    coverage: Option<Coverage>,
}

/// What became of `debug` (the debug information of `database`) over
/// `outputs`, as a comment: functions it names, prototypes taken and
/// unplaced (by reason), parameters and frame variables named.
fn debug_totals(database: &Database<'_>, debug: &DebugInfo, outputs: &[Rendered]) -> String {
    let functions: Vec<u64> = debug
        .model()
        .functions
        .keys()
        .copied()
        .filter(|&entry| database.function_at(entry).is_some())
        .collect();
    let mut unplaced: BTreeMap<&str, usize> = BTreeMap::new();
    for &entry in &functions {
        if let Some(why) = debug.unplaced(entry) {
            *unplaced.entry(why.name()).or_default() += 1;
        }
    }
    let symbols = names(database.image());
    let named = database
        .functions()
        .filter(|(_, function)| {
            !symbols.contains_key(&function.entry) && database.name(function.entry).is_some()
        })
        .count();
    let unnamed = database
        .functions()
        .filter(|(_, function)| !symbols.contains_key(&function.entry))
        .count();
    let globals = &debug.model().globals;
    let globals_unnamed = globals
        .keys()
        .filter(|address| !symbols.contains_key(address))
        .count();
    let globals_named = globals
        .keys()
        .filter(|&&address| !symbols.contains_key(&address) && database.name(address).is_some())
        .count();
    let mut total = DebugCounts::default();
    for output in outputs {
        total.add(&output.debug);
    }
    let share = |part: usize, whole: usize| {
        if whole == 0 {
            "-".to_owned()
        } else {
            #[expect(clippy::cast_precision_loss, reason = "counts are far below 2^52")]
            let share = part as f64 * 100.0 / whole as f64;
            format!("{share:.1}%")
        }
    };
    let taken = functions.len() - unplaced.values().sum::<usize>();
    let reasons: Vec<String> = unplaced
        .iter()
        .map(|(why, count)| format!("{why} {count}"))
        .collect();
    format!(
        "/* debug information: functions {} (prototypes taken {taken}, unplaced {} ({})); functions without a symbol named {named}/{unnamed} ({}); parameters named {}/{} ({}); frame variables named {}/{} ({}), typed {}; register variables (not named) {}; globals {} (without a symbol named {globals_named}/{globals_unnamed} ({})) */\n",
        functions.len(),
        functions.len() - taken,
        reasons.join(", "),
        share(named, unnamed),
        total.parameters_named,
        total.parameters,
        share(total.parameters_named, total.parameters),
        total.locals_named,
        total.locals,
        share(total.locals_named, total.locals),
        total.locals_typed,
        total.registers,
        globals.len(),
        share(globals_named, globals_unnamed),
    )
}

/// `output` (of a function of `database`) as `flags` say: its C, compiled
/// under `--stats` ([`compile_check`]), or L2's text form.
fn rendered(database: &Database<'_>, output: Output, flags: &Flags) -> Rendered {
    let debug = output.result.as_ref().map_or_else(
        |_| DebugCounts::default(),
        |decompiled| decompiled.stats.debug,
    );
    let id = output.id;
    let mut covered = None;
    let result = output.result.and_then(|decompiled| {
        if flags.stats
            && decompiled.c.is_some()
            && let Some(style) = Style::preset(&flags.style)
        {
            let style = style.with_int_spelling(flags.types);
            covered = coverage(database, id, &decompiled, &style, flags.view.opaque()).ok();
        }
        let mut asm = 0;
        let mut unknowns = Unknowns::default();
        let (text, casts, verdicts) = if let Some(c) = decompiled.c {
            asm = c.asm;
            unknowns = c.unknowns;
            // C with `__asm` blocks is no C a compiler takes: not compiled.
            let verdicts = if flags.stats && c.asm == 0 {
                compile_check(&c.text, &[("binbun_defs.h", HEADER)])
                    .map_err(|e| format!("compile check: {e}"))?
            } else {
                Vec::new()
            };
            (c.text, Some(c.casts), verdicts)
        } else {
            let declarations = database
                .declarations()
                .ok_or_else(|| "the image's code is not lifted".to_owned())?;
            let text = binbun_ast::text::print(&decompiled.l2, declarations);
            (text, None, Vec::new())
        };
        let stats = flags.stats.then(|| {
            stats_line(
                &decompiled.stats,
                casts,
                asm,
                &unknowns,
                &verdicts,
                covered.as_ref(),
            )
        });
        Ok((text, stats))
    });
    Rendered {
        entry: output.entry,
        name: output.name,
        result,
        debug,
        coverage: covered,
    }
}

/// A function's `stats`, the `casts` its C has (if printed), its `__asm`
/// blocks (`asm`: then it is not compiled, and says so) or what each
/// compiler found in it, the unknown values it prints (`unknowns`: those
/// the architecture leaves undefined are `processor-dependent`), and how
/// much of its machine code its lines came from, on one line.
fn stats_line(
    stats: &Stats,
    casts: Option<usize>,
    asm: usize,
    unknowns: &Unknowns,
    verdicts: &[Verdict],
    coverage: Option<&Coverage>,
) -> String {
    let mut line = format!(
        "gotos {}, escapes {}",
        stats.counts.gotos, stats.counts.escapes
    );
    if let Some(casts) = casts {
        let _ = write!(line, ", casts {casts}");
    }
    if stats.formats.calls() > 0 {
        let _ = write!(line, ", formats {}", stats.formats);
    }
    let variadic = stats.variadic.to_string();
    if !variadic.is_empty() {
        let _ = write!(line, ", {variadic}");
    }
    let frames = stats.frames.to_string();
    if !frames.is_empty() {
        let _ = write!(line, ", {frames}");
    }
    let debug = stats.debug.to_string();
    if !debug.is_empty() {
        let _ = write!(line, ", {debug}");
    }
    let typing = &stats.typing;
    if typing.typed || typing.refused {
        let _ = write!(
            line,
            ", solver {} (variables {}, constraints {}, steps {}, conflicts {}, disagreements {}, arrays {} ({} of structs))",
            if typing.refused { "refused" } else { "typed" },
            typing.variables,
            typing.constraints,
            typing.steps,
            typing.conflicts,
            typing.disagreements,
            typing.arrays.0,
            typing.arrays.1
        );
    }
    let counts = &stats.counts;
    if counts.tries > 0 {
        let handlers = &counts.handlers;
        let _ = write!(
            line,
            ", tries {} handlers landing/catch/catch-all/cleanup/unexpected/except/finally {}/{}/{}/{}/{}/{}/{}",
            counts.tries,
            handlers.landing,
            handlers.catch,
            handlers.catch_all,
            handlers.cleanup,
            handlers.unexpected,
            handlers.except,
            handlers.finally
        );
    }
    for (floor, count) in &stats.floors {
        let _ = write!(line, ", floor ({floor}) {count}");
    }
    for (rotated, count) in &stats.rotated {
        let _ = write!(line, ", rotated ({rotated}) {count}");
    }
    if stats.array_loops > 0 {
        let _ = write!(line, ", array loops {}", stats.array_loops);
    }
    match &stats.structure {
        Some(mismatch) => {
            let _ = write!(line, ", structure differs from L1 ({mismatch})");
        }
        None => line.push_str(", structure as L1"),
    }
    if asm > 0 {
        let _ = write!(line, ", __asm blocks {asm} (not compiled)");
    }
    unknowns_fields(&mut line, unknowns);
    for verdict in verdicts {
        let _ = write!(
            line,
            ", {} {} errors {} warnings",
            verdict.compiler, verdict.errors, verdict.warnings
        );
    }
    if let Some(coverage) = coverage {
        let _ = write!(line, ", {coverage}");
    }
    line.push_str("; passes (runs/changed/refused)");
    for (name, stats) in &stats.passes {
        let _ = write!(
            line,
            " {name} {}/{}/{}",
            stats.runs, stats.changed, stats.refused
        );
    }
    line.push_str("; analyses computed");
    for (name, count) in &stats.analyses {
        let short = name.rsplit("::").next().unwrap_or(name);
        let _ = write!(line, " {short} {count}");
    }
    line
}

/// The unknown values a function prints, as fields of its stats line:
/// those the architecture leaves undefined (`processor-dependent`), those
/// named by where they come from, then those still printed as 0; nothing
/// for none.
fn unknowns_fields(line: &mut String, unknowns: &Unknowns) {
    let Unknowns {
        architecture,
        parameter,
        call,
        landing,
        entry,
        unwritten,
        lowering,
    } = *unknowns;
    if architecture > 0 {
        let _ = write!(line, ", processor-dependent {architecture}");
    }
    if call + entry + lowering > 0 {
        let _ = write!(
            line,
            ", unknown named call/entry/lowering {call}/{entry}/{lowering}"
        );
    }
    if parameter + landing + unwritten > 0 {
        let _ = write!(
            line,
            ", unknown as 0 parameter/landing/unwritten {parameter}/{landing}/{unwritten}"
        );
    }
}

/// The text of `outputs`: each function's text (with `stats`, a comment
/// with its counts before it), or a comment saying why there is none.
fn render(outputs: &[Rendered], stats: bool) -> String {
    let mut out = String::new();
    for output in outputs {
        let name = output.name.as_deref().unwrap_or("");
        match &output.result {
            Ok((text, counts)) => {
                if stats && let Some(counts) = counts {
                    let _ = writeln!(out, "/* {:#x} {name}: {counts} */", output.entry);
                }
                out.push_str(text);
                if !text.ends_with('\n') {
                    out.push('\n');
                }
            }
            Err(message) => {
                let message = message.replace("*/", "* /");
                let _ = writeln!(
                    out,
                    "/* {:#x} {name}: not decompiled: {message} */",
                    output.entry
                );
            }
        }
        out.push('\n');
    }
    out
}
