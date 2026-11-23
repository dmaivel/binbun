#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Format strings (`binbun_decompile::format`): what the parser derives,
//! what it refuses, and an outside oracle for the types. For every format
//! string of a corpus (each distinct constant format a call to a
//! `printf`- or `scanf`-like import passes in bash, libc and libstdc++,
//! `data/formats.txt`, and edge cases), a call passing arguments of the
//! derived C types compiles with GCC and Clang under `-Wformat=2
//! -Werror=format` without a diagnostic (skipped for a compiler that is
//! not installed).

use std::fmt::Write as _;
use std::process::Command;
use std::{fs, io};

use binbun_decompile::format::{Argument, Family, Integer, Refusal, Scalar, parse};

/// The corpus: a family (`printf`, `scanf`), a tab, the format as the
/// contents of a C string literal.
const CORPUS: &str = include_str!("data/formats.txt");

/// Formats the corpus may lack: every flag, `*` width and precision, each
/// length modifier, `%%`, `%n`, `%c`, `%s`, `%p`, `scanf`'s sets and
/// assignment suppression.
const EDGES: [(Family, &str); 22] = [
    (Family::Printf, "%-+5d|% 7.3i|%'u|%#o|%#x|%-#10X|%08.3f"),
    (Family::Printf, "%*d %.*s %-*.*f"),
    (Family::Printf, "%hhd %hd %ld %lld %jd %zd %td"),
    (Family::Printf, "%hhu %hx %lo %llX %ju %zu %tu"),
    (Family::Printf, "%f %e %g %a %F %E %G %A %lf %+.2e %#g %'f"),
    (Family::Printf, "100%% %c %5c %-5c"),
    (Family::Printf, "%s %.3s %-10s %10.2s"),
    (Family::Printf, "%p %20p %-20p"),
    (Family::Printf, "%n %hhn %hn %ln %lln %jn %zn %tn"),
    (Family::Printf, "%.d %.0x %5.d"),
    (Family::Printf, "no conversions at all"),
    (Family::Scanf, "%d %i %u %o %x %X %n"),
    (Family::Scanf, "%hhd %hd %ld %lld %jd %zd %td %hhu %llx"),
    (Family::Scanf, "%f %e %g %a %lf %le %lg"),
    (Family::Scanf, "%c %5c %s %10s %p"),
    (Family::Scanf, "%[abc] %[^]x] %[]] %20[^\\n] %*[ \\t]"),
    (Family::Scanf, "%*d %*s %*c %*5x %%"),
    (Family::Scanf, "%3c%2s %4[0-9]"),
    (Family::Printf, "%-10.4s|%+08d|% .0f"),
    (Family::Printf, "%#.3o %#5.2x"),
    (Family::Scanf, "%2d:%2d:%2d"),
    (Family::Printf, "%c%c%c%%"),
];

/// The C string literal contents `literal` as bytes.
fn unescape(literal: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chars = literal.bytes().peekable();
    while let Some(byte) = chars.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        let escaped = chars.next().unwrap();
        match escaped {
            b'n' => bytes.push(b'\n'),
            b't' => bytes.push(b'\t'),
            b'r' => bytes.push(b'\r'),
            b'a' => bytes.push(7),
            b'b' => bytes.push(8),
            b'f' => bytes.push(12),
            b'v' => bytes.push(11),
            b'x' => {
                let mut value = 0u32;
                while let Some(digit) = chars.peek().and_then(|&c| char::from(c).to_digit(16)) {
                    value = value * 16 + digit;
                    chars.next();
                }
                bytes.push(u8::try_from(value).unwrap());
            }
            b'0'..=b'7' => {
                let mut value = u32::from(escaped - b'0');
                for _ in 0..2 {
                    match chars.peek() {
                        Some(&digit @ b'0'..=b'7') => {
                            value = value * 8 + u32::from(digit - b'0');
                            chars.next();
                        }
                        _ => break,
                    }
                }
                bytes.push(u8::try_from(value).unwrap());
            }
            other => bytes.push(other),
        }
    }
    bytes
}

/// The C spelling of `scalar` on x86-64 Linux (LP64).
fn scalar(scalar: Scalar) -> &'static str {
    match scalar {
        Scalar::Integer { rank, signed } => match (rank, signed) {
            (Integer::Char, true) => "signed char",
            (Integer::Char, false) => "unsigned char",
            (Integer::Short, true) => "short",
            (Integer::Short, false) => "unsigned short",
            (Integer::Int, true) => "int",
            (Integer::Int, false) => "unsigned int",
            (Integer::Long, true) => "long",
            (Integer::Long, false) => "unsigned long",
            (Integer::LongLong, true) => "long long",
            (Integer::LongLong, false) => "unsigned long long",
            (Integer::IntMax, true) => "intmax_t",
            (Integer::IntMax, false) => "uintmax_t",
            (Integer::Size, true) => "ssize_t",
            (Integer::PtrDiff, true) => "ptrdiff_t",
            (Integer::Size | Integer::PtrDiff, false) => "size_t",
        },
        Scalar::Float => "float",
        Scalar::Double => "double",
        Scalar::Char => "char",
        Scalar::VoidPointer => "void *",
    }
}

/// The C spelling of `argument`'s type.
fn spell(argument: Argument) -> String {
    match argument {
        Argument::Value(value) => scalar(value).to_owned(),
        Argument::Pointer(target) => format!("{} *", scalar(target)),
    }
}

fn int(signed: bool) -> Argument {
    Argument::Value(Scalar::Integer {
        rank: Integer::Int,
        signed,
    })
}

#[test]
fn conversions_give_their_arguments() {
    let printf = |format: &str| parse(Family::Printf, format.as_bytes());
    let scanf = |format: &str| parse(Family::Scanf, format.as_bytes());
    // `*` widths and precisions come first; `%hd` takes a promoted `int`.
    assert_eq!(
        printf("%*.*hd|%s|%%"),
        Ok(vec![
            int(true),
            int(true),
            int(true),
            Argument::Pointer(Scalar::Char)
        ])
    );
    assert_eq!(
        printf("%lu %zd %p %Lg"),
        Err(Refusal::LongDouble),
        "long double"
    );
    assert_eq!(
        printf("%lu %zd %p %f"),
        Ok(vec![
            Argument::Value(Scalar::Integer {
                rank: Integer::Long,
                signed: false
            }),
            Argument::Value(Scalar::Integer {
                rank: Integer::Size,
                signed: true
            }),
            Argument::Value(Scalar::VoidPointer),
            Argument::Value(Scalar::Double),
        ])
    );
    // scanf: pointers, `%hhd` to a `signed char`, `%f` to a `float`,
    // suppressed conversions and sets taking nothing.
    assert_eq!(
        scanf("%hhd %*d %f %lf %*[^]x] %[a-z]"),
        Ok(vec![
            Argument::Pointer(Scalar::Integer {
                rank: Integer::Char,
                signed: true
            }),
            Argument::Pointer(Scalar::Float),
            Argument::Pointer(Scalar::Double),
            Argument::Pointer(Scalar::Char),
        ])
    );
}

#[test]
fn what_the_parser_does_not_take_is_refused() {
    for (family, format, refusal) in [
        (Family::Printf, "%1$d", Refusal::Positional),
        (Family::Printf, "%*2$d", Refusal::Positional),
        (Family::Printf, "%m", Refusal::Errno),
        (Family::Printf, "%ls", Refusal::Wide),
        (Family::Printf, "%lc", Refusal::Wide),
        (Family::Printf, "%S", Refusal::Wide),
        (Family::Printf, "%Lf", Refusal::LongDouble),
        (Family::Printf, "%Id", Refusal::Extension),
        (Family::Printf, "%qd", Refusal::Extension),
        (Family::Printf, "%Ld", Refusal::Extension),
        (Family::Printf, "%b", Refusal::Extension),
        (Family::Printf, "%w32d", Refusal::Extension),
        (Family::Printf, "%y", Refusal::Invalid),
        (Family::Printf, "%", Refusal::Invalid),
        (Family::Printf, "%#d", Refusal::Invalid),
        (Family::Printf, "%0s", Refusal::Invalid),
        (Family::Printf, "%.3c", Refusal::Invalid),
        (Family::Printf, "%5n", Refusal::Invalid),
        (Family::Printf, "%--d", Refusal::Invalid),
        (Family::Printf, "% +d", Refusal::Invalid),
        (Family::Printf, "%-05d", Refusal::Invalid),
        (Family::Printf, "%05.2d", Refusal::Invalid),
        (Family::Printf, "%hf", Refusal::Invalid),
        (Family::Printf, "%lp", Refusal::Invalid),
        (Family::Scanf, "%ms", Refusal::Extension),
        (Family::Scanf, "%as", Refusal::Extension),
        (Family::Scanf, "%0d", Refusal::Invalid),
        (Family::Scanf, "%*ld", Refusal::Invalid),
        (Family::Scanf, "%[abc", Refusal::Invalid),
        (Family::Scanf, "%l[a]", Refusal::Wide),
        (Family::Scanf, "%5n", Refusal::Invalid),
        (Family::Scanf, "%'d", Refusal::Extension),
    ] {
        assert_eq!(parse(family, format.as_bytes()), Err(refusal), "{format}");
    }
}

/// The corpus and the edge cases, as (family, C literal contents).
fn corpus() -> Vec<(Family, String)> {
    let mut formats: Vec<(Family, String)> = EDGES
        .iter()
        .map(|&(family, format)| (family, format.to_owned()))
        .collect();
    for line in CORPUS.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (family, literal) = line.split_once('\t').unwrap();
        let family = match family {
            "printf" => Family::Printf,
            "scanf" => Family::Scanf,
            other => panic!("family {other}"),
        };
        formats.push((family, literal.to_owned()));
    }
    formats
}

#[test]
fn compilers_accept_the_derived_types() {
    let mut source = String::from(
        "#include <stdio.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <sys/types.h>\n",
    );
    let mut refused = [0usize; Refusal::ALL.len()];
    let mut accepted = 0;
    for (index, (family, literal)) in corpus().into_iter().enumerate() {
        let arguments = match parse(family, &unescape(&literal)) {
            Ok(arguments) => arguments,
            Err(refusal) => {
                refused[refusal.index()] += 1;
                continue;
            }
        };
        accepted += 1;
        let parameters: Vec<String> = (0..)
            .zip(&arguments)
            .map(|(position, &argument)| format!("{} a{position}", spell(argument)))
            .collect();
        let passed: String = (0..arguments.len()).fold(String::new(), |mut out, position| {
            write!(out, ", a{position}").unwrap();
            out
        });
        let parameters = if parameters.is_empty() {
            "void".to_owned()
        } else {
            parameters.join(", ")
        };
        let callee = match family {
            Family::Printf => "printf",
            Family::Scanf => "scanf",
        };
        writeln!(
            source,
            "void t{index}({parameters}) {{ {callee}(\"{literal}\"{passed}); }}"
        )
        .unwrap();
    }
    let names: Vec<String> = Refusal::ALL
        .iter()
        .zip(refused)
        .map(|(refusal, count)| format!("{} {count}", refusal.name()))
        .collect();
    eprintln!("accepted {accepted}; refused {}", names.join(", "));
    if cfg!(windows) {
        // The calls are glibc's printf and scanf, with POSIX types
        // (ssize_t, <sys/types.h>): compiled where those are the host's.
        eprintln!("skipped compiling: glibc's formats are checked on POSIX hosts");
        return;
    }
    let directory = format!("{}/format-oracle", env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(&directory).unwrap();
    let file = format!("{directory}/formats.c");
    fs::write(&file, &source).unwrap();
    for compiler in ["gcc", "clang"] {
        let output = match Command::new(compiler)
            .args([
                "-std=c11",
                "-fsyntax-only",
                "-Wformat=2",
                "-Werror=format",
                "-fdiagnostics-color=never",
                &file,
            ])
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                eprintln!("skipped: {compiler} is not installed");
                continue;
            }
            Err(error) => panic!("{compiler}: {error}"),
        };
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && diagnostics.is_empty(),
            "{compiler} on {file}:\n{diagnostics}"
        );
    }
}
