//! Building a C or C++ program against the library cargo built for the
//! test, as a user builds one: with the system's `cc` and `c++`
//! (`-Wall -Wextra -Werror -O1`, C11 and C++17); on Windows with MSVC's
//! `cl` (`/W4 /WX /O1`), found where Visual Studio installed it (as the
//! `cc` crate finds it), with the environment it needs.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The program's language.
#[derive(Clone, Copy, Debug)]
pub enum Language {
    C,
    Cpp,
}

/// Which library the program links with.
#[derive(Clone, Copy, Debug)]
pub enum Library {
    /// The shared library, found at run time by the program's rpath (on
    /// Windows beside the program, where it is copied).
    Shared,
    /// The static library with what it needs of the system.
    Static,
}

/// Where cargo put the libraries for this test: beside the test executable.
pub fn library_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("test executable");
    exe.parent().expect("deps directory").to_path_buf()
}

/// Compiles `source` into the program `out` (`.exe` added on Windows),
/// its headers `include`; panics with the compiler's output if it fails.
/// The program.
pub fn compile(
    language: Language,
    source: &Path,
    include: &Path,
    out: &Path,
    library: Library,
) -> PathBuf {
    let (mut command, out) = command(language, source, include, out, library);
    let result = command
        .output()
        .unwrap_or_else(|error| panic!("{command:?}: {error}"));
    assert!(
        result.status.success(),
        "{command:?} failed:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    out
}

#[cfg(not(windows))]
fn command(
    language: Language,
    source: &Path,
    include: &Path,
    out: &Path,
    library: Library,
) -> (Command, PathBuf) {
    let (compiler, standard) = match language {
        Language::C => ("cc", "-std=c11"),
        Language::Cpp => ("c++", "-std=c++17"),
    };
    let dir = library_dir();
    let mut command = Command::new(compiler);
    command
        .args([standard, "-Wall", "-Wextra", "-Werror", "-O1", "-I"])
        .arg(include)
        .arg(source)
        .arg("-o")
        .arg(out);
    match library {
        Library::Shared => {
            command
                .arg(format!("-L{}", dir.display()))
                .arg("-lbinbun_capi")
                .arg(format!("-Wl,-rpath,{}", dir.display()));
        }
        Library::Static => {
            // What the static library needs (`rustc --print native-static-libs`).
            let native: &[&str] = if cfg!(target_os = "macos") {
                &["-lSystem", "-lc", "-lm"]
            } else {
                &["-lpthread", "-ldl", "-lm", "-lgcc_s"]
            };
            command.arg(dir.join("libbinbun_capi.a")).args(native);
        }
    }
    (command, out.to_path_buf())
}

#[cfg(windows)]
fn command(
    language: Language,
    source: &Path,
    include: &Path,
    out: &Path,
    library: Library,
) -> (Command, PathBuf) {
    let dir = library_dir();
    let mut command = find_msvc_tools::find(std::env::consts::ARCH, "cl.exe")
        .expect("MSVC's cl.exe (Visual Studio's C++ build tools)");
    // `/MD`: the C runtime the Rust library links (`/defaultlib:msvcrt`).
    // MSVC deprecates standard C functions (`fopen`, `strncat`,
    // `strerror`) for its own `_s` ones; portable C turns that off.
    command.args([
        "/nologo",
        "/W4",
        "/WX",
        "/O1",
        "/MD",
        "/utf-8",
        "/D_CRT_SECURE_NO_WARNINGS",
    ]);
    match language {
        Language::C => command.arg("/std:c11"),
        Language::Cpp => command.args(["/std:c++17", "/EHsc"]),
    };
    let exe = out.with_extension("exe");
    command
        .arg("/I")
        .arg(include)
        .arg(source)
        .arg(format!("/Fe{}", exe.display()))
        .arg(format!("/Fo{}", out.with_extension("obj").display()))
        .arg("/link")
        .arg(format!("/LIBPATH:{}", dir.display()));
    match library {
        Library::Shared => {
            command.arg("binbun_capi.dll.lib");
            let dll = "binbun_capi.dll";
            copy_once(&dir.join(dll), &exe.with_file_name(dll));
        }
        Library::Static => {
            // What the static library needs (`rustc --print native-static-libs`).
            command.arg("binbun_capi.lib").args([
                "kernel32.lib",
                "ntdll.lib",
                "userenv.lib",
                "ws2_32.lib",
                "dbghelp.lib",
                "synchronization.lib",
            ]);
        }
    }
    (command, exe)
}

/// Copies the library `dll` to `beside` (the programs' directory) once a
/// process: a program built there before may be running, and Windows lets
/// no loaded DLL be replaced (nor a program start while it is rewritten).
#[cfg(windows)]
fn copy_once(dll: &Path, beside: &Path) {
    use std::collections::BTreeSet;
    use std::sync::{Mutex, PoisonError};

    static COPIED: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());
    let mut copied = COPIED.lock().unwrap_or_else(PoisonError::into_inner);
    if !copied.contains(beside) {
        std::fs::copy(dll, beside).unwrap_or_else(|error| panic!("{}: {error}", beside.display()));
        copied.insert(beside.to_owned());
    }
}
