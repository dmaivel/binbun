#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The parser against `cpp_demangle`: every function mangling of the
//! corpus binaries' symbols and imports that the parser accepts, its
//! parameter list rendered as C++ text, must be the parameter list of
//! `cpp_demangle`'s demangling. The comparison builds `cpp_demangle`'s
//! whole text from its name-only text (`no_params`) and ours; it never
//! parses `cpp_demangle`'s output. Where the two differ, c++filt (GNU
//! binutils, if installed) is asked the same way (its `-p` text and
//! ours against its whole text): a difference counts only if c++filt
//! disagrees with ours too (`cpp_demangle` 0.5.1 has two defects the
//! corpus meets, see [`unsettled`]).
//!
//! Binaries missing on the host are skipped; `BINBUN_ARM64_CORPUS` adds
//! the AArch64 corpus's C++ libraries. Run with `--nocapture` for the
//! coverage table (parsed, refused by production, agreeing).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use std::io::Write as _;
use std::process::{Command, Stdio};

use binbun_demangle::itanium::{self, RefQualifier};
use cpp_demangle::DemangleOptions;
use object::{Object, ObjectSymbol};

/// The manglings of `path`'s symbols, dynamic symbols and imports.
fn manglings(path: &str) -> Option<BTreeSet<String>> {
    let data = fs::read(path).ok()?;
    let file = object::File::parse(&*data).unwrap();
    let mut names: BTreeSet<String> = file
        .symbols()
        .chain(file.dynamic_symbols())
        .filter_map(|symbol| symbol.name().ok().map(str::to_owned))
        .collect();
    names.extend(
        file.imports()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter_map(|import| match import.name() {
                object::NameOrOrdinal::Name(name) => {
                    std::str::from_utf8(name).ok().map(str::to_owned)
                }
                object::NameOrOrdinal::Ordinal(_) => None,
            }),
    );
    // A static symbol table names an undefined versioned symbol with its
    // version (`_ZSt9terminatev@GLIBCXX_3.4`), which is no mangling.
    Some(
        names
            .iter()
            .filter(|name| name.starts_with("_Z"))
            .map(|name| name.split('@').next().unwrap().to_owned())
            .collect(),
    )
}

#[derive(Default)]
struct Tally {
    functions: usize,
    data: usize,
    refused: BTreeMap<&'static str, usize>,
    unrendered: usize,
    oracle_refused: usize,
    agreed: usize,
    differences: Vec<Difference>,
}

/// A function whose parameter list differs from `cpp_demangle`'s.
struct Difference {
    name: String,
    theirs: String,
    ours: String,
    /// What c++filt's text must be if it agrees with us: our return
    /// type (stated for a template), and parameters and qualifiers, around
    /// c++filt's `-p` text.
    returns: String,
    rest: String,
}

fn check(name: &str, tally: &mut Tally) {
    let symbol = match itanium::parse(name) {
        Ok(symbol) => symbol,
        Err(error) => {
            *tally.refused.entry(error.production).or_default() += 1;
            return;
        }
    };
    let Some(function) = symbol.function() else {
        tally.data += 1;
        return;
    };
    tally.functions += 1;
    let Some(parameters) = symbol.parameters_text() else {
        tally.unrendered += 1;
        return;
    };
    // The vendor suffix (` [clone .cold]`) follows the parameters in
    // both texts: compare the function without it.
    let base = name.split('.').next().unwrap();
    let Ok(oracle) = cpp_demangle::Symbol::new(base) else {
        tally.oracle_refused += 1;
        return;
    };
    let options = DemangleOptions::new().no_return_type();
    let (Ok(whole), Ok(head)) = (
        oracle.demangle_with_options(&options),
        oracle.demangle_with_options(&options.no_params()),
    ) else {
        tally.oracle_refused += 1;
        return;
    };
    // `no_params` drops the cv-qualifiers, not the ref-qualifier.
    let reference = match symbol.name().unwrap().reference {
        None => "",
        Some(RefQualifier::Lvalue) => " &",
        Some(RefQualifier::Rvalue) => " &&",
    };
    let head = head.strip_suffix(reference).unwrap_or(&head);
    let rest = format!("({parameters}){}", symbol.qualifiers_text());
    let ours = format!("{head}{rest}");
    if ours == whole {
        tally.agreed += 1;
    } else {
        let returns = function
            .returns
            .map(|ty| format!("{} ", symbol.type_text(ty).unwrap()))
            .unwrap_or_default();
        tally.differences.push(Difference {
            name: base.to_owned(),
            theirs: whole,
            ours,
            returns,
            rest,
        });
    }
}

/// c++filt's demangling of each of `names`, with `-p` (no parameters,
/// return type or qualifiers) if `bare`; `None` without c++filt.
fn cxxfilt(names: &[&str], bare: bool) -> Option<Vec<String>> {
    let mut command = Command::new("c++filt");
    if bare {
        command.arg("-p");
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    let input = names.join("\n") + "\n";
    child.stdin.take()?.write_all(input.as_bytes()).ok()?;
    let output = child.wait_with_output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    Some(text.lines().map(str::to_owned).collect())
}

/// The differences c++filt (GNU binutils) does not settle: those where
/// its text is not ours either. `cpp_demangle` 0.5.1 has two defects the
/// corpus meets: it takes a template constructor's first parameter for a
/// return type and drops it (`_ZNSsC1IPKcEET_S2_RKSaIcE`), and it puts
/// a reference or cv-qualifier inside a nested name whose scope is a
/// substituted type (`RNS1_15__upcast_resultE` as
/// `__class_type_info&::__upcast_result`).
fn unsettled(differences: Vec<Difference>) -> (usize, Vec<Difference>) {
    let names: Vec<&str> = differences.iter().map(|d| d.name.as_str()).collect();
    let (Some(whole), Some(bare)) = (cxxfilt(&names, false), cxxfilt(&names, true)) else {
        return (0, differences);
    };
    let before = differences.len();
    let left: Vec<Difference> = differences
        .into_iter()
        .zip(whole.iter().zip(&bare))
        .filter(|(difference, (whole, bare))| {
            // c++filt leaves out an empty pack's comma (`<int>`, where
            // cpp_demangle and ours print `<int, >`), and spells `Ss` and
            // `So` out.
            let rest = spell_out(&difference.rest.replace(", >", ">"));
            **whole != format!("{}{bare}{rest}", difference.returns)
        })
        .map(|(difference, _)| difference)
        .collect();
    (before - left.len(), left)
}

/// `text` with `std::string` and `std::ostream` (whole words) as c++filt
/// spells them (and a space between the closing brackets that makes).
fn spell_out(text: &str) -> String {
    let mut out = text.to_owned();
    for (short, long) in [
        (
            "std::string",
            "std::basic_string<char, std::char_traits<char>, std::allocator<char> >",
        ),
        (
            "std::ostream",
            "std::basic_ostream<char, std::char_traits<char> >",
        ),
    ] {
        let mut result = String::new();
        let mut rest = out.as_str();
        while let Some(at) = rest.find(short) {
            let after = &rest[at + short.len()..];
            let word = after
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            result.push_str(&rest[..at]);
            result.push_str(if word { short } else { long });
            rest = after;
        }
        result.push_str(rest);
        out = result;
    }
    out.replace(">>", "> >")
}
#[test]
fn parameter_lists_agree_with_cpp_demangle() {
    let fixtures = format!("{}/../../tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    let mut paths = vec![
        format!("{fixtures}/exceptions-x86_64.elf"),
        format!("{fixtures}/handlers-gcc-x86_64.elf"),
        format!("{fixtures}/handlers-clang-x86_64.elf"),
        "/usr/lib/libstdc++.so.6".to_owned(),
        "/usr/bin/bash".to_owned(),
        "/usr/lib/libc.so.6".to_owned(),
    ];
    if let Ok(corpus) = std::env::var("BINBUN_ARM64_CORPUS") {
        paths.push(format!("{corpus}/elf/libstdc++6/libstdc++.so.6.0.33"));
        paths.push(format!("{corpus}/elf/libllvm19/libLLVM.so.19.1"));
    }
    let mut differences = 0;
    for path in &paths {
        let Some(names) = manglings(path) else {
            eprintln!("{path}: missing");
            continue;
        };
        let mut tally = Tally::default();
        for name in &names {
            check(name, &mut tally);
        }
        let differing = tally.differences.len();
        let (settled, left) = unsettled(std::mem::take(&mut tally.differences));
        eprintln!(
            "{path}: {} manglings; functions parsed {}, data {}, refused {}; \
             agreeing {}, differing {differing} (c++filt agrees with ours: {settled}), \
             unrendered {}, cpp_demangle refused {}",
            names.len(),
            tally.functions,
            tally.data,
            tally.refused.values().sum::<usize>(),
            tally.agreed,
            tally.unrendered,
            tally.oracle_refused,
        );
        let mut refused: Vec<_> = tally.refused.iter().collect();
        refused.sort_by_key(|&(_, &count)| std::cmp::Reverse(count));
        for (production, count) in refused {
            eprintln!("    refused {count:>7} {production}");
        }
        for difference in left.iter().take(20) {
            eprintln!(
                "  {}\n    cpp_demangle {}\n    ours         {}",
                difference.name, difference.theirs, difference.ours
            );
        }
        differences += left.len();
    }
    assert_eq!(differences, 0);
}
