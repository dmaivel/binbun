#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Running functions from example states (`binbun::run`): values per C
//! statement and loop iteration, stubs and the stops that ask for them,
//! the machine code's run agreeing with the C, the state file, and the
//! reading view agreeing with the exact view on the statements both have.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::{Decompiled, Options as Decompiling, View};
use binbun::run::memory::{FaultKind, Fill, Memory};
use binbun::run::state::{format_value, parse_value};
use binbun::run::{
    self, CalleeKind, ExampleState, Need, Options, Recording, Stop, call_site_state, same,
};
use binbun::target::setup;
use binbun_ast::ir::{Function as Ast, Origin, Stmt, StmtId};
use binbun_loader::Image;
use binbun_semantics::Bits;
use binbun_semantics::interpret::{Machine, Value};

const BASH: &str = "/usr/bin/bash";

fn libc() -> String {
    format!(
        "{}/.cache/binbun-truth-data/glibc-r50/root/usr/lib/libc.so.6",
        std::env::home_dir().unwrap().display()
    )
}

/// `f` of the database of the image at `path`, if it exists.
fn with_database(path: &str, f: impl FnOnce(&Database<'_>)) {
    if !Path::new(path).exists() {
        eprintln!("{path} missing: skipped");
        return;
    }
    let data = std::fs::read(path).unwrap();
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    f(&database);
}

fn decompiled(database: &Database<'_>, name: &str, view: View) -> Decompiled {
    let id = database.find_function(name).unwrap();
    let options = Decompiling {
        style: None,
        view,
        ..Decompiling::default()
    };
    database.decompile(id, &options).result.unwrap()
}

fn run_named(
    database: &Database<'_>,
    name: &str,
    state: &ExampleState,
    view: View,
) -> (Decompiled, run::Run) {
    let decompiled = decompiled(database, name, view);
    let options = Options {
        view,
        ..Options::default()
    };
    let run = run::run_decompiled(
        database,
        &decompiled,
        state,
        &options,
        &AtomicBool::new(false),
    )
    .unwrap();
    (decompiled, run)
}

fn number(value: &Value) -> u64 {
    value.known().unwrap().low_u64()
}

/// A 3-element string vector at 0x10000.
const STRVEC: &str = r#"
format = 1
name = "three"
arguments = ["0x10000"]

[[region]]
address = "0x10000"
values = ["ptr:0x20000", "ptr:0x20008", "ptr:0x20010", "ptr:0"]

[[region]]
address = "0x20000"
records = [["u8:0x61", "u8:0"], ["u8:0x62", "u8:0"], ["u8:0x63", "u8:0"]]
stride = 8
"#;

/// The statement of `l2` that assigns a variable inside a loop and runs
/// three times: its trace's values and iterations.
fn loop_counter(l2: &Ast, recording: &Recording) -> Vec<(u64, u64)> {
    let candidates: Vec<Vec<(u64, u64)>> = recording
        .statements
        .iter()
        .filter(|(id, _)| matches!(l2.stmt(**id), Some(Stmt::Assign { .. })))
        .map(|(_, trace)| {
            trace
                .shown
                .iter()
                .filter_map(|o| Some((o.iteration?, number(o.values.first()?))))
                .collect::<Vec<_>>()
        })
        .filter(|values| values.len() == 3)
        .collect();
    candidates
        .into_iter()
        .find(|values| values.iter().all(|&(i, v)| i == v))
        .unwrap()
}

#[test]
fn assignments_in_conditions_show_their_values_in_both_views() {
    // set_posix_options copies a byte of its argument to each variable a
    // null-terminated table of pointers lists: the exact view tests
    // `if ((v = table[i]) == 0) return i;` in a loop, the reading view
    // `do … while ((v = table[i]) != 0);`. Each decision's occurrence shows
    // the pointer its condition assigned, the table's 0 last.
    let state = ExampleState::parse(
        r#"
format = 1
name = "options"
arguments = ["0x10000"]

[[region]]
address = "0x10000"
values = ["u64:0x0101010101010101", "u64:0x0101010101010101"]
"#,
    )
    .unwrap();
    with_database(BASH, |database| {
        let mut shown = Vec::new();
        for view in [View::Exact, View::Reading] {
            let (decompiled, run) = run_named(database, "set_posix_options", &state, view);
            let Stop::Returned(Some(count)) = &run.c.stop else {
                panic!("{view:?}: {}", run.c.stop);
            };
            let l2 = &decompiled.l2;
            let deciding: Vec<StmtId> = run
                .c
                .statements
                .keys()
                .copied()
                .filter(|&id| assigns_in_condition(l2, id))
                .collect();
            let [decision] = deciding.as_slice() else {
                panic!("{view:?}: {deciding:?}");
            };
            let values: Vec<u64> = run.c.statements[decision]
                .shown
                .iter()
                .filter_map(|occurrence| occurrence.values.first().map(number))
                .collect();
            // One pointer per variable set, then the terminator.
            assert_eq!(values.len() as u64, number(count), "{view:?}: {values:x?}");
            assert_eq!(values.last(), Some(&0), "{view:?}: {values:x?}");
            assert!(
                values[..values.len() - 1].iter().all(|&v| v != 0),
                "{view:?}: {values:x?}"
            );
            shown.push(values);
        }
        assert_eq!(shown[0], shown[1]);
    });
}

/// Whether statement `id` of `l2` decides on a condition holding an
/// assignment expression.
fn assigns_in_condition(l2: &Ast, id: StmtId) -> bool {
    use binbun_ast::ir::Expr;
    let Some(
        &(Stmt::If { condition, .. }
        | Stmt::While { condition, .. }
        | Stmt::DoWhile { condition, .. }
        | Stmt::For { condition, .. }),
    ) = l2.stmt(id)
    else {
        return false;
    };
    let mut work = vec![condition];
    while let Some(at) = work.pop() {
        let Some(expr) = l2.expr(at) else { continue };
        if matches!(expr, Expr::Assign { .. }) {
            return true;
        }
        work.extend(expr.operands(l2));
    }
    false
}

#[test]
fn strvec_len_counts_a_three_element_vector_in_both_views() {
    with_database(BASH, |database| {
        let state = ExampleState::parse(STRVEC).unwrap();
        for view in [View::Exact, View::Reading] {
            let (decompiled, run) = run_named(database, "strvec_len", &state, view);
            let Stop::Returned(Some(value)) = &run.c.stop else {
                panic!("{view:?}: {}", run.c.stop);
            };
            assert_eq!(number(value), 3);
            // The counter's statement: 1, 2, 3 in iterations 1, 2, 3.
            assert_eq!(
                loop_counter(&decompiled.l2, &run.c),
                [(1, 1), (2, 2), (3, 3)]
            );
            assert_eq!(run.c.iterations.values().copied().collect::<Vec<_>>(), [3]);
            let machine = run.machine.as_ref().unwrap();
            assert_eq!(machine.stop, Stop::Returned(None), "{view:?}");
            assert_eq!(run.agree, Some(true), "{view:?}");
            // `add rax, 1` ran three times, writing rax 1, 2, 3 (and flags).
            let rax = database.declarations().unwrap().find("rax").unwrap();
            let add = &machine.traces[&0xe29a0];
            assert_eq!(add.count, 3);
            let written: Vec<u64> = add
                .shown
                .iter()
                .map(|writes| number(&writes.iter().find(|(id, _)| *id == rax).unwrap().1))
                .collect();
            assert_eq!(written, [1, 2, 3]);
            assert!(add.shown[0].len() > 1, "the flags too");
        }
    });
}

#[test]
fn a_call_needing_a_stub_stops_and_runs_with_one() {
    with_database(&libc(), |database| {
        let mut state = ExampleState::parse(
            "format = 1\nname = \"hello\"\narguments = [\"0x30000\"]\n\
             [[region]]\naddress = \"0x30000\"\nstring = \"hello\"\n",
        )
        .unwrap();
        let (_, run) = run_named(database, "__strdup", &state, View::Exact);
        let Stop::NeedsStub { callee, need } = &run.c.stop else {
            panic!("{}", run.c.stop);
        };
        assert_eq!(*need, Need::Unresolved);
        assert_eq!(callee.kind, CalleeKind::Unresolved);
        // The machine code stops at the same call, and says so.
        assert_eq!(run.agree, Some(true));

        let strlen = format!("{:#x}", callee.address);
        state.stubs = toml_stubs(&format!(
            "[[stub]]\ntarget = \"{strlen}\"\nreturns = \"5\"\n\
             [[stub]]\ntarget = \"malloc\"\nreturns = \"0\"\n"
        ));
        let (_, run) = run_named(database, "__strdup", &state, View::Exact);
        assert_eq!(
            run.c.stop,
            Stop::Returned(Some(Value::defined(Bits::from_u64(64, 0))))
        );
        let malloc = run
            .c
            .calls
            .iter()
            .find(|call| call.callee.name.as_deref() == Some("malloc"));
        assert_eq!(number(&malloc.unwrap().arguments[0]), 6);
        assert_eq!(run.agree, Some(true));

        // The state for malloc from that call site: its argument recorded.
        let caller = decompiled(database, "__strdup", View::Exact);
        let call = malloc.unwrap();
        let provenance = &caller.l2.provenance;
        let origins = match call.at {
            binbun_ast::ir::CallSite::Stmt(id) => provenance.stmt(id),
            binbun_ast::ir::CallSite::Expr(id) => provenance.expr(id),
        };
        let at = origins.iter().find_map(instruction).unwrap();
        let made = call_site_state(&caller, at, Some((&state, &run.c)), "malloc 6").unwrap();
        assert_eq!(made.arguments, ["0x6"]);
        let unknown = call_site_state(&caller, at, None, "malloc ?").unwrap();
        assert_eq!(unknown.arguments, ["undefined"]);
    });
}

fn toml_stubs(text: &str) -> Vec<run::state::Stub> {
    ExampleState::parse(&format!("format = 1\nname = \"s\"\n{text}"))
        .unwrap()
        .stubs
}

/// The instruction an origin names, if it names one.
fn instruction(origin: &Origin) -> Option<u64> {
    if let Origin::Instruction(address) = origin {
        Some(*address)
    } else {
        None
    }
}

#[test]
fn values_parse_with_undefined_digits_and_round_trip() {
    let value = parse_value("0x1?3", 16).unwrap();
    assert_eq!(value.bits, Bits::from_u64(16, 0x103));
    assert_eq!(value.undefined, Bits::from_u64(16, 0xf0));
    assert_eq!(format_value(&value), "0x1?3");
    assert_eq!(
        format_value(&parse_value("undefined", 8).unwrap()),
        "undefined"
    );
    assert_eq!(number(&parse_value("-1", 32).unwrap()), 0xffff_ffff);
    assert!(parse_value("0x123", 8).is_err());
    let state = ExampleState::parse(STRVEC).unwrap();
    assert_eq!(
        ExampleState::parse(&state.to_toml().unwrap()).unwrap(),
        state
    );
    assert!(ExampleState::parse("format = 2\nname = \"later\"").is_err());
}

#[test]
fn memory_is_undefined_in_regions_and_faults_outside() {
    let data = std::fs::read(format!(
        "{}/../../tests/fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        "loops-x86_64.elf"
    ));
    let Ok(data) = data else {
        return;
    };
    let image = Image::parse(&data).unwrap();
    let mut memory = Memory::new(&image, Fill::Unmapped);
    memory.map(0x5000_0000..0x5000_0010);
    memory.set(0x5000_0000, (0x2a, 0));
    let loaded = memory.load(0x5000_0000, 2).unwrap();
    assert_eq!(loaded.bits, Bits::from_u64(16, 0x2a));
    assert_eq!(loaded.undefined, Bits::from_u64(16, 0xff00));
    assert_eq!(memory.byte(0x5000_0010), Err(FaultKind::Unmapped));
    assert_eq!(memory.byte(0x8000_0000_0000), Err(FaultKind::NonCanonical));
    let hashed = Memory::new(&image, Fill::Hashed);
    assert!(hashed.byte(0x5000_0010).is_ok());
}

/// What identifies a statement across views: its instructions, its kind
/// and its value's top operation with its constant operands (a pointer
/// loop's `p + 8` and the index loop it becomes, `i + 1`, are different
/// statements of the same instruction).
type Key = (Vec<u64>, String);

fn key(l2: &Ast, id: StmtId) -> Option<Key> {
    use binbun_ast::ir::Expr;
    let top = |value| match l2.expr(value) {
        Some(&Expr::Binary(op, a, b)) => {
            let constant = |id| match l2.expr(id) {
                Some(Expr::Const(bits)) => format!("{:#x}", bits.low_u64()),
                _ => "_".to_owned(),
            };
            format!("{op:?} {} {}", constant(a), constant(b))
        }
        Some(expr) => format!("{:?}", core::mem::discriminant(expr)),
        None => String::new(),
    };
    let kind = match *l2.stmt(id)? {
        Stmt::Assign { value, .. } => format!("assign {}", top(value)),
        Stmt::Call { .. } => "call".to_owned(),
        Stmt::Return(value) => format!("return {}", value.map(top).unwrap_or_default()),
        Stmt::Intrinsic { .. }
        | Stmt::Expr(_)
        | Stmt::If { .. }
        | Stmt::While { .. }
        | Stmt::DoWhile { .. }
        | Stmt::For { .. }
        | Stmt::Switch { .. }
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_)
        | Stmt::Trap(_)
        | Stmt::Unreachable
        | Stmt::Escape { .. }
        | Stmt::Try { .. }
        | Stmt::VaStart { .. } => return None,
    };
    let mut addresses: Vec<u64> = l2
        .provenance
        .stmt(id)
        .iter()
        .filter_map(instruction)
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    (!addresses.is_empty()).then_some((addresses, kind))
}

/// Each statement's values, by key, where its key is unique.
fn keyed(l2: &Ast, recording: &Recording) -> BTreeMap<Key, Vec<Value>> {
    let mut seen: BTreeMap<_, Option<Vec<Value>>> = BTreeMap::new();
    for (&id, trace) in &recording.statements {
        let Some(key) = key(l2, id) else { continue };
        let values: Vec<Value> = trace
            .shown
            .iter()
            .filter_map(|o| o.values.first().copied())
            .collect();
        seen.entry(key)
            .and_modify(|slot| *slot = None)
            .or_insert(Some(values));
    }
    seen.into_iter()
        .filter_map(|(key, values)| Some((key, values?)))
        .collect()
}

#[derive(Default, Debug)]
struct Tally {
    pairs: usize,
    shared: usize,
    agreed: usize,
    disagreed: Vec<String>,
    stops: BTreeMap<(&'static str, &'static str), usize>,
    times: Vec<(Duration, u64)>,
}

#[test]
#[ignore = "decompiles 200 of bash's functions in both views and runs each from a random state"]
fn the_reading_view_agrees_with_the_exact_view_on_shared_statements() {
    with_database(BASH, |database| {
        let mut functions: Vec<_> = database
            .functions()
            .map(|(id, function)| (function.entry, id))
            .collect();
        functions.sort_unstable();
        let step = functions.len() / 400;
        let mut tally = Tally::default();
        for &(entry, id) in functions.iter().step_by(step.max(1)) {
            if tally.pairs == 200 {
                break;
            }
            pair(database, entry, id, &mut tally);
        }
        tally.times.sort_unstable();
        let total: Duration = tally.times.iter().map(|&(time, _)| time).sum();
        eprintln!(
            "{} pairs: {} shared statements, {} agree, {} disagree; stops {:?}; \
             run time median {:?}, max {:?} ({} steps), total {total:?}",
            tally.pairs,
            tally.shared,
            tally.agreed,
            tally.disagreed.len(),
            tally.stops,
            tally.times[tally.times.len() / 2].0,
            tally.times.last().unwrap().0,
            tally.times.last().unwrap().1,
        );
        for difference in tally.disagreed.iter().take(10) {
            eprintln!("  {difference}");
        }
        let longest = tally.times.iter().max_by_key(|&&(_, steps)| steps).unwrap();
        eprintln!("longest run: {} statements in {:?}", longest.1, longest.0);
        assert_eq!(tally.pairs, 200);
        assert_eq!(tally.disagreed, Vec::<String>::new());
        assert!(tally.agreed > 200);
    });
}

/// Runs function `id` (at `entry`) in both views from its random state.
fn pair(database: &Database<'_>, entry: u64, id: binbun::cfg::FunctionId, tally: &mut Tally) {
    let decompile = |view| {
        let options = Decompiling {
            style: None,
            view,
            ..Decompiling::default()
        };
        database.decompile(id, &options).result.ok()
    };
    let (Some(exact), Some(reading)) = (decompile(View::Exact), decompile(View::Reading)) else {
        return;
    };
    let setup = setup(database.image(), entry).unwrap();
    let state = ExampleState::random(&setup, entry, "random");
    let options = |view| Options {
        view,
        steps: 20_000,
        depth: 2,
        instructions: false,
        ..Options::default()
    };
    let cancel = AtomicBool::new(false);
    let start = Instant::now();
    let Ok(a) = run::run_decompiled(database, &exact, &state, &options(View::Exact), &cancel)
    else {
        return;
    };
    tally.times.push((
        start.elapsed(),
        a.c.statements.values().map(|t| t.count).sum(),
    ));
    let Ok(b) = run::run_decompiled(database, &reading, &state, &options(View::Reading), &cancel)
    else {
        return;
    };
    tally.pairs += 1;
    *tally
        .stops
        .entry((a.c.stop.kind(), b.c.stop.kind()))
        .or_default() += 1;
    let (a_values, b_values) = (keyed(&exact.l2, &a.c), keyed(&reading.l2, &b.c));
    for (key, a_values) in &a_values {
        let Some(b_values) = b_values.get(key) else {
            continue;
        };
        tally.shared += 1;
        let agree = a_values.iter().zip(b_values).all(|(a, b)| same(a, b));
        if agree {
            tally.agreed += 1;
        } else {
            tally.disagreed.push(format!(
                "{entry:#x} at {:x?}: exact {:?}, reading {:?}",
                key.0,
                a_values.iter().map(run::show).collect::<Vec<_>>(),
                b_values.iter().map(run::show).collect::<Vec<_>>()
            ));
        }
    }
}
