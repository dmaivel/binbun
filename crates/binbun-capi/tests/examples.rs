//! The C and C++ examples (`examples/c`, `examples/cpp`), built as a user
//! builds them (`-Wall -Wextra -Werror`, C11 and C++17; MSVC's `/W4 /WX` on
//! Windows, `support/compile.rs`) against the library cargo built for this
//! test, run with no arguments, on bytes and on the checked-in fixtures;
//! each one's output is checked for what it is meant to show.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;

#[path = "support/compile.rs"]
#[expect(dead_code, reason = "the examples link the shared library only")]
mod compile;

use compile::{Language, Library};

/// The repository's root.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Builds `source` into `name`, linked with the shared library beside the
/// test executable; once, as tests share programs (and one running while
/// another rewrites it fails). Into a directory of this process's: a runner
/// that gives each test its own process (nextest) builds the same programs
/// in several at once.
fn build(language: Language, source: &Path, name: &str) -> PathBuf {
    static BUILT: Mutex<BTreeMap<String, PathBuf>> = Mutex::new(BTreeMap::new());
    let mut built = BUILT.lock().unwrap();
    if let Some(out) = built.get(name) {
        return out.clone();
    }
    let mine =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("examples-{}", std::process::id()));
    fs::create_dir_all(&mine).unwrap();
    let out = compile::compile(
        language,
        source,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("include"),
        &mine.join(name),
        Library::Shared,
    );
    built.insert(name.to_owned(), out.clone());
    out
}

fn c(name: &str) -> PathBuf {
    let source = root().join("examples/c").join(format!("{name}.c"));
    build(Language::C, &source, &format!("example_c_{name}"))
}

fn cpp(name: &str) -> PathBuf {
    let source = root().join("examples/cpp").join(format!("{name}.cpp"));
    build(Language::Cpp, &source, &format!("example_cpp_{name}"))
}

/// Runs `program` with `args`.
fn run(program: &Path, args: &[&str]) -> Output {
    Command::new(program)
        .args(args)
        .current_dir(root())
        .env_remove("LD_LIBRARY_PATH")
        .output()
        .unwrap()
}

/// What `program` prints with `args`; it must succeed. Lines end in `\n`
/// (Windows' C runtime writes `\r\n`, its text mode).
fn stdout(program: &Path, args: &[&str]) -> String {
    let output = run(program, args);
    assert!(
        output.status.success(),
        "{} {args:?}: {}",
        program.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let out = String::from_utf8(output.stdout).unwrap();
    if cfg!(windows) {
        out.replace("\r\n", "\n")
    } else {
        out
    }
}

/// Asserts that `program` fails with `args`, saying `message` on stderr.
fn fails(program: &Path, args: &[&str], message: &str) {
    let output = run(program, args);
    assert!(
        !output.status.success(),
        "{} {args:?} succeeded",
        program.display()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(message), "{stderr}");
}

const QUICK_START: &str = "\
0x401000  push rbp
0x401001  mov rbp, rsp
0x401004  xor eax, eax
0x401006  pop rbp
0x401007  ret \n";

/// Every C and C++ example, the arguments its header says it defaults to,
/// and a line it then prints.
const DEFAULTS: [(&str, &[&str], &str); 12] = [
    ("c/quick_start", &[], "0x401000  push rbp"),
    ("cpp/quick_start", &[], "0x401000  push rbp"),
    (
        "c/decode_any",
        &["554889e5e8000000005dc3"],
        "0000000000001004  e8 00 00 00 00           call 0x1009                  call   reads rip rsp; writes rip rsp",
    ),
    (
        "cpp/decode_any",
        &["554889e5e8000000005dc3"],
        "0000000000001004  e8 00 00 00 00           call 0x1009                  call   reads rip rsp; writes rip rsp",
    ),
    (
        "c/disassemble",
        &["554889e5e8000000005dc3"],
        "0000000000001004  e8 00 00 00 00          call 0x1009",
    ),
    (
        "cpp/disassemble",
        &["554889e5e8000000005dc3"],
        "0000000000001004  e8 00 00 00 00          call 0x1009",
    ),
    (
        "c/instruction_info",
        &["48014310"],
        "0x1000: add qword ptr [rbx+0x10], rax",
    ),
    (
        "cpp/instruction_info",
        &["48014310"],
        "0x1000: add qword ptr [rbx+0x10], rax",
    ),
    (
        "c/color_tokens",
        &["488b4310", "e800000000", "c3"],
        "0x00001004  \x1b[1;34mcall\x1b[0m \x1b[35m0x1009\x1b[0m",
    ),
    (
        "cpp/color_tokens",
        &["488b4310", "e800000000", "c3"],
        "0x00001004  \x1b[1;34mcall\x1b[0m \x1b[35m0x1009\x1b[0m",
    ),
    (
        "c/list_calls",
        &["tests/fixtures/program-x86_64.elf"],
        "0x000011d8  call 0x1190                               classify",
    ),
    (
        "cpp/list_calls",
        &["tests/fixtures/program-x86_64.elf"],
        "0x000011d8  call 0x1190                               classify",
    ),
];

/// `printed` without the line naming the file read, which names it as it
/// was given.
fn without_file_name(printed: &str) -> Vec<&str> {
    printed
        .lines()
        .filter(|line| !line.starts_with("calls in .text of "))
        .collect()
}

#[test]
fn every_example_runs_with_no_arguments() {
    let listed: BTreeSet<String> = DEFAULTS
        .iter()
        .map(|(example, _, _)| (*example).to_owned())
        .collect();
    let mut found = BTreeSet::new();
    for (language, extension) in [("c", "c"), ("cpp", "cpp")] {
        for entry in fs::read_dir(root().join("examples").join(language)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == extension) {
                let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
                found.insert(format!("{language}/{stem}"));
            }
        }
    }
    assert_eq!(listed, found, "every example has its defaults checked");

    for (example, defaults, line) in DEFAULTS {
        let program = match example.split_once('/').unwrap() {
            ("c", name) => c(name),
            (_, name) => cpp(name),
        };
        let bare = stdout(&program, &[]);
        assert!(bare.lines().any(|l| l == line), "{example}:\n{bare}");
        assert_eq!(
            without_file_name(&bare),
            without_file_name(&stdout(&program, defaults)),
            "{example} with no arguments runs as with {defaults:?}"
        );
    }
}

#[test]
fn quick_starts_print_the_first_instructions() {
    assert_eq!(stdout(&c("quick_start"), &[]), QUICK_START);
    assert_eq!(stdout(&cpp("quick_start"), &[]), QUICK_START);
}

/// What `examples/rust/decode_any.rs` prints with no arguments, and with
/// `--arch aarch64`; `python/tests/test_examples.py` holds the Python one
/// to the same.
const DECODE_ANY_X86_64: &str = "\
0000000000001000  55                       push rbp                     push   reads rbp rsp; writes rsp
0000000000001001  48 89 e5                 mov rbp, rsp                 mov    reads rsp; writes rbp
0000000000001004  e8 00 00 00 00           call 0x1009                  call   reads rip rsp; writes rip rsp
0000000000001009  5d                       pop rbp                      pop    reads rsp; writes rbp rsp
000000000000100a  c3                       ret                          ret    reads rsp; writes rip rsp
";
const DECODE_ANY_AARCH64: &str = "\
0000000000001000  fd 7b bf a9  stp x29, x30, [sp, #-0x10]!  stp    reads x29 x30 sp; writes sp
0000000000001004  fd 03 00 91  mov x29, sp                  mov    reads sp; writes x29
0000000000001008  01 00 00 94  bl 0x100c                    bl     reads -; writes x30
000000000000100c  fd 7b c1 a8  ldp x29, x30, [sp], #0x10    ldp    reads sp; writes x29 x30 sp
0000000000001010  c0 03 5f d6  ret                          ret    reads x30; writes -
";

#[test]
fn decode_any_prints_what_the_rust_example_prints() {
    for program in [c("decode_any"), cpp("decode_any")] {
        assert_eq!(stdout(&program, &[]), DECODE_ANY_X86_64);
        assert_eq!(stdout(&program, &["--arch", "aarch64"]), DECODE_ANY_AARCH64);
        let x86 = stdout(&program, &["--arch", "x86-32", "55", "06", "c3"]);
        assert!(
            x86.lines()
                .nth(1)
                .unwrap()
                .ends_with("push   reads es ss esp; writes esp"),
            "{x86}"
        );
        assert_eq!(
            stdout(&program, &["06", "c3"]).lines().next().unwrap(),
            "0000000000001000  06                       (invalid instruction)"
        );
        let a64 = stdout(&program, &["--arch", "aarch64", "c0035fd6", "ff"]);
        assert!(
            a64.ends_with("  ff           (instruction is truncated)\n"),
            "{a64}"
        );
        fails(&program, &["zz"], "not hexadecimal");
        fails(&program, &["--arch", "mips"], "unknown architecture");
    }
}

#[test]
fn disassemble_shows_addresses_bytes_and_bad_bytes() {
    for program in [c("disassemble"), cpp("disassemble")] {
        let x86 = stdout(&program, &["55", "4889e5", "e800000000", "06", "c3"]);
        let lines: Vec<&str> = x86.lines().collect();
        assert!(lines[0].starts_with("0000000000001000  55 "), "{x86}");
        assert!(lines[0].ends_with("push rbp"), "{x86}");
        assert!(lines[2].contains("e8 00 00 00 00") && lines[2].ends_with("call 0x1009"));
        assert!(
            lines[3].starts_with("0000000000001009  06")
                && lines[3].contains("bad: invalid instruction")
        );
        let a64 = stdout(
            &program,
            &[
                "--arch",
                "aarch64",
                "--address",
                "0x2000",
                "fd7bbfa9",
                "c0035fd6",
                "ff",
            ],
        );
        let lines: Vec<&str> = a64.lines().collect();
        assert!(
            lines[0].starts_with("0000000000002000  fd 7b bf a9")
                && lines[0].ends_with("stp x29, x30, [sp, #-0x10]!")
        );
        assert!(lines[1].ends_with("ret"));
        assert!(lines[2].contains("bad: instruction is truncated"));
        let bare = stdout(&program, &["--arch", "aarch64"]);
        assert!(bare.contains("94 bl 0x100c"), "{bare}");
        fails(&program, &["zz"], "not hexadecimal");
    }
}

#[test]
fn list_calls_names_the_fixtures_calls() {
    for program in [c("list_calls"), cpp("list_calls")] {
        let x86 = stdout(&program, &["tests/fixtures/program-x86_64.elf"]);
        assert!(x86.contains("0x000011d8  call 0x1190"), "{x86}");
        assert!(
            x86.lines()
                .any(|l| l.starts_with("0x000011d8") && l.ends_with("classify"))
        );
        assert!(
            x86.lines()
                .any(|l| l.starts_with("0x000010af") && l.contains("(through a pointer)"))
        );
        assert!(x86.ends_with("10 calls\n"), "{x86}");
        let a64 = stdout(&program, &["tests/fixtures/dozen-aarch64.elf"]);
        assert!(a64.lines().any(|l| l.starts_with("0x00210154")
            && l.contains("bl 0x210140")
            && l.ends_with("leaf_sum")));
        assert!(a64.ends_with("4 calls\n"), "{a64}");
        fails(
            &program,
            &["tests/fixtures/program-i686.exe"],
            "not a 64-bit little-endian ELF",
        );
        fails(&program, &["tests/fixtures/no-such-file"], "No such file");
    }
}

#[test]
fn instruction_info_shows_access_flags_and_implicit_registers() {
    for program in [c("instruction_info"), cpp("instruction_info")] {
        let add = stdout(&program, &["48014310"]);
        assert!(
            add.starts_with("0x1000: add qword ptr [rbx+0x10], rax\n"),
            "{add}"
        );
        assert!(
            add.contains("0  read/write  64 bits  [rbx+0x10] (8 bytes)"),
            "{add}"
        );
        assert!(add.contains("1  read        64 bits  rax"), "{add}");
        assert!(add.contains("rflags (implicit)"), "{add}");
        assert!(add.contains("written: cf pf af zf sf of"), "{add}");
        let ret = stdout(&program, &["--aarch64", "c0035fd6"]);
        assert!(ret.contains("implicit reads: x30"), "{ret}");
        let stp = stdout(&program, &["--aarch64", "fd7bbfa9"]);
        assert!(stp.contains("memory: store of 16 bytes"), "{stp}");
        assert!(
            stp.contains("write      memory at [sp, written back]"),
            "{stp}"
        );
        assert_eq!(stdout(&program, &["--aarch64"]), stp);
        fails(&program, &["0f"], "instruction is truncated");
    }
    // The C++ one names the flags and the branch on both architectures.
    let program = cpp("instruction_info");
    let cmp = stdout(&program, &["--aarch64", "1f0001eb"]);
    assert!(cmp.contains("flags read: -; written: n z c v"), "{cmp}");
    let bl = stdout(&program, &["--aarch64", "01000094"]);
    assert!(bl.contains("implicit reads: -; writes: x30"), "{bl}");
    assert!(bl.ends_with("  branch: call to 0x1004\n"), "{bl}");
}

#[test]
fn color_tokens_colour_each_kind() {
    for program in [c("color_tokens"), cpp("color_tokens")] {
        let x86 = stdout(&program, &["488b4310"]);
        assert_eq!(
            x86,
            "0x00001000  \x1b[1;34mmov\x1b[0m \x1b[32mrax\x1b[0m, \x1b[36mqword\x1b[0m \x1b[36mptr\x1b[0m \
             [\x1b[32mrbx\x1b[0m+\x1b[33m0x10\x1b[0m]\n"
        );
        let a64 = stdout(&program, &["--aarch64", "00000094"]);
        assert!(
            a64.contains("\x1b[1;34mbl\x1b[0m \x1b[35m0x1000\x1b[0m"),
            "{a64:?}"
        );
        let bare = stdout(&program, &["--aarch64"]);
        assert!(
            bare.starts_with("0x00001000  \x1b[1;34mldr\x1b[0m"),
            "{bare:?}"
        );
        assert_eq!(bare.lines().count(), 3, "{bare:?}");
    }
}
