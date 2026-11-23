//! Lowering (`binbun_decompile::lower`) and the L2 passes on the corpus:
//! every function recovered from the x86-64 ELF fixtures, the system's
//! libc and bash lowers to L2 that passes binbun-ast's verifier (lowering
//! runs it), goes through the whole L2 pipeline decompilation runs
//! ([`l2_passes`]: structuring, copies, dead code, rules, divisions,
//! loops, signs; the verifier after each change), and then passes the
//! structure check against L1; for the fixtures and libc, that final L2
//! runs as L1 from random states up to the first call, exit or escape.
//! The fixtures with debug files and the glibc build with its debug file
//! (if present) lower and run so with their debug information as input
//! too: its names and types change no meaning.
//! The reading view (`binbun::decompile::View::Reading`) is checked the
//! same way against the L1 it is made from, the exact L1 under its
//! assumption ([`reading_l1`]): on the fixtures, libc and bash, structure
//! and the differential. That is the sound comparison: every run of the
//! exact L1 that takes no fault the assumption rules out runs the same in
//! the assumed L1 (each folded branch goes the way it went), so agreement
//! with the assumed L1 is agreement with the exact L1 on those runs; on
//! the others the reading view goes on where the machine faults, as the
//! assumption says.
//! Prints failures by cause, escapes by kind, variables before and after
//! coalescing and after the passes, and the time taken (`--nocapture`).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

use binbun::analysis::{Seeds, analyse, names, type_library};
use binbun::data::ImageData;
use binbun::debug::DebugInfo;
use binbun::decompile::{
    Interfaces, Prepared, View, callers, exceptions, l2_passes, lower_function, reading_l1,
    stream_parallel, threads,
};
use binbun::lift::ImageEnvironment;
use binbun::manglings::Manglings;
use binbun::memory::ImageOracle;
use binbun::progress::Progress;
use binbun::prototypes::{Imports, LibraryPrototypes};
use binbun::references::References;
use binbun::target::setup;
use binbun_ast::ir::{Callee, Expr, ExprId, Function as Ast, Place, Stmt, StmtId};
use binbun_decompile::itanium::Exceptions;
use binbun_decompile::pass::L2Env;
use binbun_decompile::validate::{differential, random_states, structure};
use binbun_loader::Image;

const FIXTURES: &[&str] = &[
    "program-x86_64.elf",
    "floats-x86_64.elf",
    "exceptions-x86_64.elf",
    "handlers-gcc-x86_64.elf",
    "handlers-clang-x86_64.elf",
    "atomics-x86_64.elf",
    "unaligned-x86_64.elf",
    "classes-gcc-x86_64.elf",
    "classes-clang-x86_64.elf",
    "opaque-x86_64.elf",
    "rodata-x86_64.elf",
    "chars-x86_64.elf",
    "variadic-gcc-x86_64.elf",
    "variadic-clang-x86_64.elf",
    "globals-x86_64.elf",
    "interfaces-x86_64.elf",
    // A call of a function that never throws in an exception table's
    // range: its unwind edge is no way control goes.
    "nothrow-x86_64.elf",
    // The x87 environment stored and loaded: the reading view's empty
    // stack settles its tag word.
    "x87-x86_64.elf",
];

const LIBC: &str = "/usr/lib/libc.so.6";
const BASH: &str = "/usr/bin/bash";

/// The fixtures with a separate debug file, by name and debug file.
const DEBUG_FIXTURES: [(&str, &str); 5] = [
    ("program-x86_64.elf", "program-x86_64.debug"),
    ("exceptions-x86_64.elf", "exceptions-x86_64.debug"),
    ("handlers-gcc-x86_64.elf", "handlers-gcc-x86_64.debug"),
    ("handlers-clang-x86_64.elf", "handlers-clang-x86_64.debug"),
    ("rodata-x86_64.elf", "rodata-x86_64.debug"),
];

/// A glibc build and its debug file (`binbun eval types`' libc pair),
/// under `$HOME/.cache/binbun-truth-data/glibc-r50/root`.
const LIBC_PAIR: (&str, &str) = ("usr/lib/libc.so.6", "usr/lib/debug/usr/lib/libc.so.6.debug");

fn fixture(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// What lowering a corpus gave.
#[derive(Default)]
struct Tally {
    functions: usize,
    lowered: usize,
    /// Functions that do not lift (L1's concern, not lowering's).
    unlifted: usize,
    /// Lowering failures by cause.
    failures: BTreeMap<String, Vec<String>>,
    /// Structure mismatches.
    structure: Vec<String>,
    escapes: BTreeMap<String, usize>,
    values: usize,
    variables: usize,
    copies: usize,
    over_budget: usize,
    /// Variables the final L2 reads or writes.
    used: usize,
    /// Functions a pass of the pipeline broke (the verifier failed).
    broken: Vec<String>,
    /// Differential runs, agreements, skips; differences.
    runs: usize,
    agreed: usize,
    skipped: usize,
    differences: Vec<String>,
    lowering: Duration,
    passes: Duration,
    checking: Duration,
}

impl Tally {
    /// Adds what `other` counted (a function's tally, in the stream's order).
    fn add(&mut self, other: Self) {
        self.functions += other.functions;
        self.lowered += other.lowered;
        self.unlifted += other.unlifted;
        for (cause, list) in other.failures {
            self.failures.entry(cause).or_default().extend(list);
        }
        self.structure.extend(other.structure);
        for (kind, count) in other.escapes {
            *self.escapes.entry(kind).or_default() += count;
        }
        self.values += other.values;
        self.variables += other.variables;
        self.copies += other.copies;
        self.over_budget += other.over_budget;
        self.used += other.used;
        self.broken.extend(other.broken);
        self.runs += other.runs;
        self.agreed += other.agreed;
        self.skipped += other.skipped;
        self.differences.extend(other.differences);
        self.lowering += other.lowering;
        self.passes += other.passes;
        self.checking += other.checking;
    }

    fn report(&self, name: &str) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{name}: {} functions, {} lowered, {} not lifted, {} failed",
            self.functions,
            self.lowered,
            self.unlifted,
            self.failures.values().map(Vec::len).sum::<usize>()
        );
        for (cause, list) in &self.failures {
            let _ = writeln!(out, "  failure {cause}: {} (e.g. {})", list.len(), list[0]);
        }
        let _ = writeln!(out, "  structure mismatches: {}", self.structure.len());
        for mismatch in self.structure.iter().take(10) {
            let _ = writeln!(out, "    {mismatch}");
        }
        let _ = writeln!(out, "  escapes: {:?}", self.escapes);
        let _ = writeln!(
            out,
            "  values with variables {} -> variables {} ({:.2} per function -> {:.2}) -> after the passes {} ({:.2}); edge copies {}; over budget {}",
            self.values,
            self.variables,
            ratio(self.values, self.lowered),
            ratio(self.variables, self.lowered),
            self.used,
            ratio(self.used, self.lowered),
            self.copies,
            self.over_budget
        );
        let _ = writeln!(out, "  broken by a pass: {}", self.broken.len());
        for broken in self.broken.iter().take(10) {
            let _ = writeln!(out, "    {broken}");
        }
        let _ = writeln!(
            out,
            "  differential: {} runs, {} agreed, {} skipped, {} differences",
            self.runs,
            self.agreed,
            self.skipped,
            self.differences.len()
        );
        for difference in self.differences.iter().take(20) {
            let _ = writeln!(out, "    {difference}");
        }
        let _ = writeln!(
            out,
            "  time: lowering {:.2?}, passes {:.2?}, checks {:.2?}",
            self.lowering, self.passes, self.checking
        );
        out
    }

    fn assert_clean(&self, name: &str) {
        let report = self.report(name);
        println!("{report}");
        assert!(self.failures.is_empty(), "{report}");
        assert!(self.broken.is_empty(), "{report}");
        assert!(self.structure.is_empty(), "{report}");
        assert!(self.differences.is_empty(), "{report}");
    }
}

fn ratio(a: usize, b: usize) -> f64 {
    #[allow(clippy::cast_precision_loss, reason = "a ratio for a report")]
    let (a, b) = (a as f64, b.max(1) as f64);
    a / b
}

/// The cause of a lowering failure: its message up to the first detail.
fn cause(message: &str) -> String {
    let mut words: Vec<&str> = message.split_whitespace().take(6).collect();
    words.retain(|word| !word.starts_with("0x") && !word.starts_with('v'));
    words.join(" ")
}

/// How many variables `l2`'s body reads or writes (as the printer
/// declares them): every variable an expression or place of a statement
/// in the body names, parameters included.
fn used_variables(l2: &Ast) -> usize {
    let mut used = BTreeSet::new();
    let mut exprs: Vec<ExprId> = Vec::new();
    let mut place = |place: &Place, exprs: &mut Vec<ExprId>| match *place {
        Place::Var(var) => {
            used.insert(var);
        }
        Place::Memory { address, .. } => exprs.push(address),
    };
    let mut work: Vec<&Vec<StmtId>> = vec![&l2.body];
    while let Some(block) = work.pop() {
        for &id in block {
            let stmt = l2.stmt(id).unwrap();
            work.extend(stmt.blocks());
            match stmt {
                Stmt::Assign {
                    place: target,
                    value,
                } => {
                    exprs.push(*value);
                    place(target, &mut exprs);
                }
                Stmt::Call { results, call } => {
                    if let Callee::Expr(callee) = call.callee {
                        exprs.push(callee);
                    }
                    exprs.extend(&call.arguments);
                    for result in results {
                        place(result, &mut exprs);
                    }
                }
                Stmt::Intrinsic {
                    results,
                    inputs: operands,
                    ..
                }
                | Stmt::Escape {
                    operands, results, ..
                } => {
                    exprs.extend(operands);
                    for result in results {
                        place(result, &mut exprs);
                    }
                }
                &Stmt::Expr(id)
                | &Stmt::If { condition: id, .. }
                | &Stmt::While { condition: id, .. }
                | &Stmt::DoWhile { condition: id, .. }
                | &Stmt::For { condition: id, .. }
                | &Stmt::Switch { scrutinee: id, .. }
                | &Stmt::Return(Some(id)) => exprs.push(id),
                Stmt::Return(None)
                | Stmt::Break(_)
                | Stmt::Continue(_)
                | Stmt::Label(_)
                | Stmt::Goto(_)
                | Stmt::Trap(_)
                | Stmt::Unreachable
                | Stmt::Try { .. }
                | Stmt::VaStart { .. } => {}
            }
        }
    }
    let mut seen = BTreeSet::new();
    while let Some(id) = exprs.pop() {
        if !seen.insert(id) {
            continue;
        }
        let expr = l2.expr(id).unwrap();
        if let Expr::Var(var) | Expr::AddressOf(var) = *expr {
            used.insert(var);
        }
        exprs.extend(expr.operands(l2));
    }
    used.len()
}

/// Lowers every function of the image at `path` as
/// [`stream`](binbun::decompile::stream) hands it over, on [`threads`]
/// threads ([`stream_parallel`]), with the debug information at `debug`
/// as input if given, in `view`; with `states` > 0, runs each from that
/// many random states.
fn corpus(path: &str, debug: Option<&str>, states: usize, view: View, tally: &mut Tally) {
    let data = std::fs::read(path).unwrap();
    let image = Image::parse(&data).unwrap();
    let debug = debug.map(|debug| {
        let model = binbun_debuginfo::info::read(&std::fs::read(debug).unwrap(), &data).unwrap();
        DebugInfo::new(model, &image)
    });
    let library = type_library(&image).unwrap();
    let program = analyse(&image, Seeds::ALL, &library).unwrap();
    let (references, summaries) =
        References::build(&image, &program, threads(), &Progress::default());
    let imports = Imports::new(&image, &program);
    let manglings = Manglings::new(&image);
    let objects = debug.as_ref().map(DebugInfo::objects).unwrap_or_default();
    let corpus = Corpus {
        path,
        image: &image,
        prototypes: imports.prototypes(&library, &manglings, debug.as_ref()),
        data: ImageData::new(&image, names(&image), &objects, program.data()),
        exceptions: exceptions(&image, imports.thunk_names(), imports.nothrow(&library)),
        oracle: ImageOracle::new(&image),
        states,
        view,
    };
    let callers = callers(
        &image,
        &program,
        &summaries,
        &references,
        &corpus.prototypes,
        &corpus.data,
        &[],
        threads(),
        view.assumes_arguments_set(),
    );
    stream_parallel(
        &image,
        &program,
        &summaries,
        &callers,
        &[],
        threads(),
        |_, prepared, known| {
            let mut one = Tally {
                functions: 1,
                ..Tally::default()
            };
            match prepared {
                Ok(prepared) => corpus.check(&prepared, known, &mut one),
                Err(_) => one.unlifted += 1,
            }
            one
        },
        |one| tally.add(one),
    );
}

/// What lowering one image's functions shares.
struct Corpus<'a> {
    path: &'a str,
    image: &'a Image<'a>,
    prototypes: LibraryPrototypes<'a>,
    data: ImageData<'a>,
    exceptions: Exceptions,
    oracle: ImageOracle<'a>,
    /// Random states each function runs from (none: no differential).
    states: usize,
    /// Exact, or the reading view (from the assumed L1).
    view: View,
}

impl Corpus<'_> {
    /// Lowers `prepared` (in the reading view: its assumed L1) with the
    /// interfaces `known` and checks it against the L1 it is lowered from.
    fn check(&self, prepared: &Prepared, known: &Interfaces, tally: &mut Tally) {
        let (path, image) = (self.path, self.image);
        let reading;
        let prepared = match self.view {
            View::Exact => prepared,
            View::Reading => match reading_l1(image, prepared, &[]) {
                Ok((assumed, _)) => {
                    reading = assumed;
                    &reading
                }
                Err(message) => {
                    tally
                        .broken
                        .push(format!("{path} {:#x}: {message}", prepared.l1.entry));
                    return;
                }
            },
        };
        let l1 = &prepared.l1;
        let entry = l1.entry;
        let start = Instant::now();
        let lowered = lower_function(image, prepared, known, &self.prototypes, &self.data);
        tally.lowering += start.elapsed();
        let (mut l2, mapping, counts) = match lowered {
            Ok(lowered) => lowered,
            Err(message) => {
                tally
                    .failures
                    .entry(cause(&message))
                    .or_default()
                    .push(format!("{path} {entry:#x}: {message}"));
                return;
            }
        };
        tally.lowered += 1;
        tally.values += counts.values;
        tally.variables += counts.variables;
        tally.copies += counts.copies;
        tally.over_budget += usize::from(counts.over_budget);
        for stmt in &l2.stmts {
            if let Stmt::Escape { kind, .. } = stmt {
                *tally.escapes.entry(format!("{kind:?}")).or_default() += 1;
            }
        }
        let start = Instant::now();
        let environment = ImageEnvironment::new(image, &[]).unwrap();
        let env = L2Env {
            declarations: environment.declarations(),
            exceptions: &self.exceptions,
            feeds: None,
        };
        let passed = l2_passes(&mut l2, &env, &[]);
        tally.passes += start.elapsed();
        if let Err(message) = passed {
            tally.broken.push(format!("{path} {entry:#x}: {message}"));
            return;
        }
        tally.used += used_variables(&l2);
        let start = Instant::now();
        if let Err(mismatch) = structure(l1, &l2, &self.exceptions) {
            tally
                .structure
                .push(format!("{path} {entry:#x}: {mismatch}"));
        }
        if self.states > 0 {
            let setup = setup(image, entry).unwrap();
            let states = random_states(&setup, self.states, entry);
            let report = differential(l1, &l2, &mapping, &setup, &self.oracle, &states);
            tally.runs += report.runs;
            tally.agreed += report.agreed;
            tally.skipped += report.skipped();
            if let Some(difference) = report.differences.first() {
                tally.differences.push(format!(
                    "{path} {entry:#x}: state {}: {}",
                    difference.state, difference.message
                ));
            }
        }
        tally.checking += start.elapsed();
    }
}

#[test]
fn fixture_functions_lower_and_run_as_l1() {
    let mut tally = Tally::default();
    for name in FIXTURES {
        corpus(&fixture(name), None, 64, View::Exact, &mut tally);
    }
    assert!(tally.lowered >= 40, "only {} lowered", tally.lowered);
    tally.assert_clean("fixtures");
}

#[test]
fn fixture_functions_in_the_reading_view_lower_and_run_as_the_assumed_l1() {
    let mut tally = Tally::default();
    for name in FIXTURES {
        corpus(&fixture(name), None, 64, View::Reading, &mut tally);
    }
    assert!(tally.lowered >= 40, "only {} lowered", tally.lowered);
    tally.assert_clean("fixtures, reading view");
}

#[test]
fn fixture_functions_lower_and_run_as_l1_with_debug_information() {
    let mut tally = Tally::default();
    for (name, debug) in DEBUG_FIXTURES {
        corpus(
            &fixture(name),
            Some(&fixture(debug)),
            64,
            View::Exact,
            &mut tally,
        );
    }
    assert!(tally.lowered >= 30, "only {} lowered", tally.lowered);
    tally.assert_clean("fixtures with debug information");
}

#[test]
#[ignore = "lowers and runs all of a glibc build with its debug information"]
fn libc_functions_lower_and_run_as_l1_with_debug_information() {
    let Ok(home) = std::env::var("HOME") else {
        return;
    };
    let root = format!("{home}/.cache/binbun-model-data/glibc-r50/root");
    let (libc, debug) = (
        format!("{root}/{}", LIBC_PAIR.0),
        format!("{root}/{}", LIBC_PAIR.1),
    );
    if !Path::new(&libc).exists() || !Path::new(&debug).exists() {
        return;
    }
    let mut tally = Tally::default();
    corpus(&libc, Some(&debug), 16, View::Exact, &mut tally);
    assert!(tally.lowered >= 1000, "only {} lowered", tally.lowered);
    tally.assert_clean("libc with debug information");
}

#[test]
fn libc_functions_lower_and_run_as_l1() {
    if !Path::new(LIBC).exists() {
        return;
    }
    let mut tally = Tally::default();
    corpus(LIBC, None, 16, View::Exact, &mut tally);
    assert!(tally.lowered >= 1000, "only {} lowered", tally.lowered);
    tally.assert_clean("libc");
}

#[test]
fn libc_functions_in_the_reading_view_lower_and_run_as_the_assumed_l1() {
    if !Path::new(LIBC).exists() {
        return;
    }
    let mut tally = Tally::default();
    corpus(LIBC, None, 16, View::Reading, &mut tally);
    assert!(tally.lowered >= 1000, "only {} lowered", tally.lowered);
    tally.assert_clean("libc, reading view");
}

#[test]
fn bash_functions_lower() {
    if !Path::new(BASH).exists() {
        return;
    }
    let mut tally = Tally::default();
    corpus(BASH, None, 0, View::Exact, &mut tally);
    assert!(tally.lowered >= 1000, "only {} lowered", tally.lowered);
    tally.assert_clean("bash");
}

#[test]
fn bash_functions_in_the_reading_view_lower() {
    if !Path::new(BASH).exists() {
        return;
    }
    let mut tally = Tally::default();
    corpus(BASH, None, 0, View::Reading, &mut tally);
    assert!(tally.lowered >= 1000, "only {} lowered", tally.lowered);
    tally.assert_clean("bash, reading view");
}

#[test]
#[ignore = "runs all of bash's reading view from 16 random states (about 15 minutes)"]
fn bash_functions_in_the_reading_view_lower_and_run_as_the_assumed_l1() {
    if !Path::new(BASH).exists() {
        return;
    }
    let mut tally = Tally::default();
    corpus(BASH, None, 16, View::Reading, &mut tally);
    assert!(tally.lowered >= 1000, "only {} lowered", tally.lowered);
    tally.assert_clean("bash, reading view");
}
