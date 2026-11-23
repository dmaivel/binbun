//! binbun-typegen: writes a type database (JSON Lines) from C headers,
//! Windows metadata or syzlang descriptions.
//!
//! ```sh
//! cd tools/typegen && cargo build --release --features headers,winmd
//! target/release/binbun-typegen --arch x86_64 --os linux --env gnu \
//!     --include-system -o libc.jsonl umbrella.h -- -D_GNU_SOURCE
//! target/release/binbun-typegen --arch x86_64 --os windows --env msvc \
//!     --winmd Windows.Win32.winmd -o win32.jsonl
//! target/release/binbun-typegen --arch x86_64 --os linux --env gnu \
//!     --syzlang sys.txt --syzlang socket.txt --resolve -o syscalls.jsonl
//! ```
//!
//! - `--arch`, `--os`, `--env`: the target (required); `--pointer-size N`
//!   (default 8 for 64-bit architectures, else 4).
//! - `--input TEXT` (repeatable): an input to record in the header, such
//!   as a package version.
//! - `-o FILE`: where to write (default standard output).
//! - Headers (the default; feature `headers`): the header files, then
//!   after `--` arguments for clang. `--include-system` keeps declarations
//!   in system headers; `--from PATH` (repeatable) keeps only those in
//!   the header files or directories given (a type they use is still
//!   converted); `--library NAME` declares the functions as NAME's (a
//!   DLL's), not any library's; `--except FILE` (repeatable) leaves out
//!   the functions another database already declares; `--exports DLL`
//!   keeps only the functions the PE image DLL exports by name;
//!   `--keep KEY` (repeatable) keeps only the types the functions refer
//!   to and the type KEY, with what they refer to.
//!   `--only-library NAME` (repeatable) keeps only the functions declared
//!   as NAME's (a DLL's or driver's, case-insensitively).
//!   `--rename-library FROM=TO` (repeatable) declares the functions
//!   declared as FROM's (case-insensitively) as TO's, before
//!   `--only-library` keeps them: the WDK's metadata declares the native
//!   API the kernel exports to drivers (`Rtl*`, `Zw*`, `DbgPrint`) as
//!   ntdll.dll's, which exports the same functions to user mode.
//!   `--gcc-builtins DIR`: GCC's `builtins.def`, `builtin-types.def` and
//!   `builtin-attrs.def` in DIR (`$(gcc -print-file-name=plugin)/include`)
//!   add the object-size checking functions (`__memcpy_chk`) the headers
//!   do not declare ([`binbun_typegen::gcc`]).
//! - `--winmd FILE` (feature `winmd`; repeatable: the files read as one,
//!   as the WDK's metadata with the Win32 metadata whose types it uses).
//!   `--layouts` lays the records out as MSVC does (field offsets, size,
//!   alignment), where the metadata states none.
//! - `--syzlang FILE` (repeatable); `--resolve` resolves flag values by
//!   compiling and running a probe (trusted input only); `--skip-include
//!   TEXT` (repeatable) leaves out the descriptions' includes containing
//!   TEXT from the probe; `--syscall-numbers FILE` numbers the calls from
//!   the target's kernel table (`asm/unistd_64.h`); `--probe-runner
//!   PROGRAM` runs the probe as `PROGRAM probe` (an emulator such as
//!   `qemu-aarch64`, for a probe `$CC` builds for another architecture).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{env, fs};

use binbun_typedb::database::{Header, SCHEMA_VERSION, Source, Target};
use binbun_typedb::jsonl;
use binbun_typegen::{Declarations, syzlang};
use object::read::NameOrOrdinal;
use object::{File, Object as _};

#[derive(Debug, Default)]
struct Args {
    arch: Option<String>,
    os: Option<String>,
    env: Option<String>,
    pointer_size: Option<u8>,
    inputs: Vec<String>,
    output: Option<PathBuf>,
    include_system: bool,
    from: Vec<PathBuf>,
    library: Option<String>,
    except: Vec<PathBuf>,
    exports: Option<PathBuf>,
    keep: Vec<String>,
    gcc_builtins: Option<PathBuf>,
    winmd: Vec<PathBuf>,
    layouts: bool,
    only_libraries: Vec<String>,
    /// `--rename-library`'s: from, to.
    renamed_libraries: Vec<(String, String)>,
    syzlang: Vec<PathBuf>,
    resolve: bool,
    skip_includes: Vec<String>,
    probe_runner: Option<String>,
    syscall_numbers: Option<PathBuf>,
    headers: Vec<PathBuf>,
    /// Arguments for clang, after `--`.
    clang: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        let mut value = |name: &str| iter.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--arch" => args.arch = Some(value("--arch")?),
            "--os" => args.os = Some(value("--os")?),
            "--env" => args.env = Some(value("--env")?),
            "--pointer-size" => {
                let size = value("--pointer-size")?;
                args.pointer_size =
                    Some(size.parse().map_err(|_| format!("--pointer-size {size}"))?);
            }
            "--input" => args.inputs.push(value("--input")?),
            "-o" | "--output" => args.output = Some(value("-o")?.into()),
            "--include-system" => args.include_system = true,
            "--from" => args.from.push(value("--from")?.into()),
            "--library" => args.library = Some(value("--library")?),
            "--except" => args.except.push(value("--except")?.into()),
            "--exports" => args.exports = Some(value("--exports")?.into()),
            "--keep" => args.keep.push(value("--keep")?),
            "--gcc-builtins" => args.gcc_builtins = Some(value("--gcc-builtins")?.into()),
            "--winmd" => args.winmd.push(value("--winmd")?.into()),
            "--layouts" => args.layouts = true,
            "--only-library" => args.only_libraries.push(value("--only-library")?),
            "--rename-library" => {
                let pair = value("--rename-library")?;
                let (from, to) = pair
                    .split_once('=')
                    .ok_or_else(|| format!("--rename-library {pair}: not FROM=TO"))?;
                args.renamed_libraries
                    .push((from.to_owned(), to.to_owned()));
            }
            "--syzlang" => args.syzlang.push(value("--syzlang")?.into()),
            "--resolve" => args.resolve = true,
            "--skip-include" => args.skip_includes.push(value("--skip-include")?),
            "--probe-runner" => args.probe_runner = Some(value("--probe-runner")?),
            "--syscall-numbers" => args.syscall_numbers = Some(value("--syscall-numbers")?.into()),
            "--" => args.clang.extend(iter.by_ref()),
            other if other.starts_with('-') => return Err(format!("unknown option {other}")),
            header => args.headers.push(header.into()),
        }
    }
    Ok(args)
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let arch = args.arch.clone().ok_or("--arch is required")?;
    let pointer_size = args.pointer_size.unwrap_or(
        if matches!(
            arch.as_str(),
            "x86_64" | "aarch64" | "riscv64" | "ppc64" | "s390x"
        ) {
            8
        } else {
            4
        },
    );
    let target = Target {
        arch,
        os: args.os.clone().ok_or("--os is required")?,
        env: args.env.clone().ok_or("--env is required")?,
        pointer_size,
    };
    let mut generator = format!("binbun-typegen {}", env!("CARGO_PKG_VERSION"));
    let (source, declarations) = if !args.winmd.is_empty() {
        let paths: Vec<&Path> = args.winmd.iter().map(PathBuf::as_path).collect();
        (Source::Winmd, parse_winmd(&paths, &target, args.layouts)?)
    } else if !args.syzlang.is_empty() {
        let paths: Vec<&Path> = args.syzlang.iter().map(PathBuf::as_path).collect();
        let numbers = match &args.syscall_numbers {
            Some(path) => syzlang::numbers(
                &fs::read_to_string(path)
                    .map_err(|error| format!("{}: {error}", path.display()))?,
            )
            .map_err(|error| format!("{}: {error}", path.display()))?,
            None => std::collections::BTreeMap::new(),
        };
        let options = syzlang::Options {
            target: &target,
            resolve: args.resolve,
            skip_includes: &args.skip_includes,
            probe_runner: args.probe_runner.as_deref(),
            numbers: &numbers,
        };
        (Source::Syzlang, syzlang::parse(&paths, &options)?)
    } else {
        (
            Source::Header,
            parse_headers(&args, &target, &mut generator)?,
        )
    };
    let mut declarations = declarations;
    select(&args, &mut declarations)?;
    let summary = format!(
        "{} functions, {} types",
        declarations.functions.len(),
        declarations.types.len()
    );
    let header = Header {
        binbun_typedb: SCHEMA_VERSION,
        source,
        target,
        generator,
        inputs: args.inputs,
    };
    let database = declarations.into_database(header)?;
    let text = jsonl::write(&database).map_err(|error| error.to_string())?;
    match &args.output {
        Some(path) => {
            fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))?;
            eprintln!("{}: {summary}", path.display());
        }
        None => print!("{text}"),
    }
    Ok(())
}

/// Keeps the functions `args` asks for (`--except`, `--exports`,
/// `--only-library`, after `--rename-library`) and the types they and
/// `--keep` need, as `--library`'s if given.
fn select(args: &Args, declarations: &mut Declarations) -> Result<(), String> {
    let mut excepted = std::collections::BTreeSet::new();
    for path in &args.except {
        let text =
            fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let other = jsonl::parse(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        excepted.extend(other.functions.into_iter().map(|function| function.name));
    }
    declarations
        .functions
        .retain(|function| !excepted.contains(&function.name));
    if let Some(path) = &args.exports {
        let exported = exports(path)?;
        declarations
            .functions
            .retain(|function| exported.contains(&function.name));
    }
    for function in &mut declarations.functions {
        if let Some((_, to)) = args.renamed_libraries.iter().find(|(from, _)| {
            function
                .library
                .as_deref()
                .is_some_and(|library| from.eq_ignore_ascii_case(library))
        }) {
            function.library = Some(to.clone());
        }
    }
    if !args.only_libraries.is_empty() {
        declarations.functions.retain(|function| {
            function.library.as_deref().is_some_and(|library| {
                args.only_libraries
                    .iter()
                    .any(|only| only.eq_ignore_ascii_case(library))
            })
        });
    }
    if !args.keep.is_empty() {
        declarations.keep(&args.keep)?;
    }
    if let Some(library) = &args.library {
        for function in &mut declarations.functions {
            function.library = Some(library.clone());
        }
    }
    Ok(())
}

#[cfg(feature = "headers")]
fn parse_headers(
    args: &Args,
    target: &Target,
    generator: &mut String,
) -> Result<Declarations, String> {
    if args.headers.is_empty() {
        return Err("no headers given".to_owned());
    }
    generator.push_str(", ");
    generator.push_str(&clang::get_version());
    let headers: Vec<&Path> = args.headers.iter().map(PathBuf::as_path).collect();
    let from = args
        .from
        .iter()
        .map(|place| {
            place
                .canonicalize()
                .map_err(|error| format!("{}: {error}", place.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut options = binbun_typegen::headers::Options {
        target,
        args: &args.clang,
        include_system: args.include_system,
        from: &from,
        extra: "",
    };
    let declarations = binbun_typegen::headers::parse(&headers, &options)?;
    let Some(dir) = &args.gcc_builtins else {
        return Ok(declarations);
    };
    // GCC's functions the headers do not declare, read with them again so
    // that clang spells their types as the headers'.
    let declared: std::collections::BTreeSet<&str> = declarations
        .functions
        .iter()
        .map(|function| function.name.as_str())
        .collect();
    let extra = binbun_typegen::gcc::fortified(dir, |name| !declared.contains(name))?;
    if extra.is_empty() {
        return Ok(declarations);
    }
    options.extra = &extra;
    binbun_typegen::headers::parse(&headers, &options)
}

/// The names the PE image at `path` exports.
fn exports(path: &Path) -> Result<std::collections::BTreeSet<String>, String> {
    let error = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
    let data = fs::read(path).map_err(|e| error(&e))?;
    let file = File::parse(&*data).map_err(|e| error(&e))?;
    if !matches!(file, File::Pe32(_) | File::Pe64(_)) {
        return Err(error(&"not a PE image"));
    }
    let exports = file.exports().map_err(|e| error(&e))?;
    exports
        .filter_map(|export| match export {
            Ok(export) => match export.name() {
                NameOrOrdinal::Name(name) => Some(Ok(String::from_utf8_lossy(name).into_owned())),
                NameOrOrdinal::Ordinal(_) => None,
            },
            Err(e) => Some(Err(error(&e))),
        })
        .collect()
}

#[cfg(not(feature = "headers"))]
fn parse_headers(_: &Args, _: &Target, _: &mut String) -> Result<Declarations, String> {
    Err("built without the `headers` feature".to_owned())
}

#[cfg(feature = "winmd")]
fn parse_winmd(paths: &[&Path], target: &Target, layouts: bool) -> Result<Declarations, String> {
    use binbun_typegen::winmd::{Layouts, parse};
    let layouts = if layouts {
        Layouts::Computed
    } else {
        Layouts::Stated
    };
    parse(paths, target, layouts)
}

#[cfg(not(feature = "winmd"))]
fn parse_winmd(_: &[&Path], _: &Target, _: bool) -> Result<Declarations, String> {
    Err("built without the `winmd` feature".to_owned())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("binbun-typegen: {error}");
            ExitCode::FAILURE
        }
    }
}
