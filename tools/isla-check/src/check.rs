//! One A64 word: binbun's L0 against every path isla finds through
//! sail-arm.
//!
//! Per path, z3 first checks that the path is feasible once Sail's reads
//! are tied to binbun's initial state (a path made infeasible by the
//! linking would make the check vacuous), then looks for an initial state
//! on the path where the two end differently:
//! - the path takes an exception: binbun must trap, or for a supervisor
//!   call (EC 0x15) enter the system without trapping;
//! - otherwise binbun must not trap, enter the system or run out of loop
//!   unrolling, and must leave every register as Sail does (registers
//!   Sail does not write unchanged; BTYPE as `BTypeNext`, 0 unless a
//!   branch sets it), continue at the same address (its jump target if it
//!   transfers control, else the next instruction), leave the same memory,
//!   and read and write exactly the same bytes.
//!
//! Undefined values in the L0 are free: the check holds for every choice
//! of them.
//!
//! Sail's calls of the overrides' abstract `binbun_<intrinsic>` functions
//! are binbun's intrinsic of that name: their results are tied to the
//! uninterpreted function `binbun_semantics::smt` makes of the intrinsic,
//! on the same arguments, so both sides compute the same unknown value. A
//! word whose L0 calls any other intrinsic with outputs (a value the
//! processor supplies) is unsupported: Sail models what the intrinsic
//! stands for its own way, so the two cannot be tied.

use std::collections::BTreeMap;
use std::fmt;

use binbun_semantics::ir::Stmt;
use binbun_semantics::smt::{self, Final, Options, Script, State, Term};
use binbun_semantics::{Declarations, Semantics};

use crate::context;
use crate::model::Model;
use crate::solver;
use crate::trace::{self, Initial, Trace};

/// The result for one word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// binbun agrees with Sail on every path.
    Equivalent {
        /// The paths isla found.
        paths: usize,
        /// How many of them take an exception.
        exceptions: usize,
    },
    /// An initial state where they differ.
    Counterexample(Counterexample),
    /// The word could not be checked (and why).
    Unsupported(String),
}

/// A state where binbun and Sail end differently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counterexample {
    /// The path (isla's order).
    pub path: usize,
    /// The exception Sail takes on it, if any (`ESR_EL1, EC 0x26`).
    pub exception: Option<String>,
    /// What differs (`x0`, `n`, `next pc`, `memory`, `trap`, …).
    pub differences: Vec<String>,
    /// The initial values of the registers Sail reads.
    pub inputs: Vec<(String, String)>,
    /// For each difference with values: binbun's and Sail's.
    pub values: Vec<(String, String, String)>,
    /// For each memory or footprint difference: the address it is at.
    pub addresses: Vec<(String, String)>,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Equivalent { paths, exceptions } => {
                write!(
                    f,
                    "equivalent ({paths} paths, {exceptions} taking exceptions)"
                )
            }
            Self::Counterexample(counterexample) => write!(f, "{counterexample}"),
            Self::Unsupported(why) => write!(f, "unsupported: {why}"),
        }
    }
}

impl fmt::Display for Counterexample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "counterexample on path {}", self.path)?;
        if let Some(exception) = &self.exception {
            write!(f, " (Sail takes an exception: {exception})")?;
        }
        write!(f, ": differs in {}", self.differences.join(", "))?;
        if !self.inputs.is_empty() {
            let inputs: Vec<String> = self
                .inputs
                .iter()
                .map(|(name, value)| format!("{name} = {value}"))
                .collect();
            write!(f, "\n  initial: {}", inputs.join(", "))?;
        }
        for (what, binbun, sail) in &self.values {
            write!(f, "\n  {what}: binbun {binbun}, Sail {sail}")?;
        }
        for (what, address) in &self.addresses {
            write!(f, "\n  {what} differs at {address}")?;
        }
        Ok(())
    }
}

/// Checks `semantics` (binbun's L0 for `word` at `pc`, over
/// `declarations`) against Sail.
pub fn check(
    model: &Model<'_>,
    word: u32,
    pc: u64,
    semantics: &Semantics,
    declarations: &Declarations,
) -> Verdict {
    check_paths(model, word, pc, semantics, declarations).unwrap_or_else(Verdict::Unsupported)
}

/// What one path's queries ask, to read the answers back.
struct Query {
    exception: Option<String>,
    labels: Vec<String>,
    inputs: Vec<String>,
    /// Label, binbun's value, Sail's value (symbols).
    values: Vec<(String, Term, Term)>,
    /// Label, the address it compares at (a symbol).
    addresses: Vec<(String, Term)>,
}

fn check_paths(
    model: &Model<'_>,
    word: u32,
    pc: u64,
    semantics: &Semantics,
    declarations: &Declarations,
) -> Result<Verdict, String> {
    if let Some(name) = supplied(&semantics.body, declarations) {
        return Err(format!(
            "L0 intrinsic `{name}` supplies values Sail models differently"
        ));
    }
    let run = model.run(word, pc);
    if let Some(error) = run.errors.first() {
        return Err(format!("isla: {error} ({} paths failed)", run.errors.len()));
    }
    if run.paths.is_empty() {
        return Err("isla finds no path".into());
    }
    let options = Options::default();
    let mut script = Script::new();
    let initial = script.initial_state(declarations, "s.", &options);
    let done = script
        .encode(semantics, declarations, &initial, "l0", &options)
        .map_err(|error| format!("binbun's L0: {error}"))?;
    let names: BTreeMap<String, String> = declarations
        .registers
        .iter()
        .zip(&initial.registers)
        .map(|(info, term)| (info.name.to_owned(), term.as_str().to_owned()))
        .collect();
    if let Some(start) = names.get("pc") {
        script.assert(&smt::eq(&Term::new(start.clone()), &smt::literal(64, pc)));
    }
    let next = smt::ite(
        &done.transferred,
        &done.target,
        &smt::literal(64, pc.wrapping_add(4)),
    );
    let next = script.name("l0.next", &smt::sort(64), next);
    let start = Initial {
        registers: names,
        memory: initial.memory.as_str().to_owned(),
    };
    let mut queries = Vec::new();
    for path in &run.paths {
        let mut trace = trace::read(model, path, &start, pc)?;
        link_intrinsics(&mut script, declarations, &mut trace)?;
        if trace.exception.is_none() && !trace.unmapped.is_empty() {
            let unmapped: Vec<&str> = trace.unmapped.iter().map(String::as_str).collect();
            return Err(format!(
                "Sail writes {}, which binbun does not model",
                unmapped.join(", ")
            ));
        }
        let ends = Ends {
            declarations,
            done: &done,
            initial: &initial,
            next: &next,
        };
        queries.push(query(&mut script, &ends, &trace));
    }
    // For debugging: the last script sent to z3.
    if let Ok(path) = std::env::var("ISLA_CHECK_SCRIPT") {
        std::fs::write(&path, script.as_str()).map_err(|error| format!("{path}: {error}"))?;
    }
    let output = solver::run(script.as_str())?;
    answers(&output, &queries)
}

/// The intrinsics with outputs that the checker ties to Sail:
/// `compute_pac` and `exclusive_store` to the overrides' abstract
/// `binbun_compute_pac` and `binbun_exclusive_store` (the monitors'
/// verdict in `AArch64.ExclusiveMonitorsPass`),
/// `system_register` to Sail's reads of the registers it stands for
/// (`trace`'s `SYSTEM_REGISTERS`).
const LINKED: [&str; 3] = ["compute_pac", "exclusive_store", "system_register"];

/// The name of the first intrinsic with outputs in `body` that is not
/// [`LINKED`], if any.
fn supplied(body: &[Stmt], declarations: &Declarations) -> Option<&'static str> {
    body.iter().find_map(|statement| match statement {
        Stmt::Intrinsic {
            intrinsic, outputs, ..
        } if !outputs.is_empty() => {
            let name = declarations
                .intrinsic(*intrinsic)
                .map_or("?", |info| info.name);
            (!LINKED.contains(&name)).then_some(name)
        }
        Stmt::If {
            then, otherwise, ..
        } => supplied(then, declarations).or_else(|| supplied(otherwise, declarations)),
        Stmt::Loop(body) | Stmt::Atomic(body) => supplied(body, declarations),
        Stmt::Read { .. }
        | Stmt::Write { .. }
        | Stmt::Load { .. }
        | Stmt::Store { .. }
        | Stmt::Break
        | Stmt::Trap(_)
        | Stmt::Jump { .. }
        | Stmt::Call { .. }
        | Stmt::Return { .. }
        | Stmt::SystemCall
        | Stmt::Intrinsic { .. } => None,
    })
}

/// binbun's side of the comparison.
struct Ends<'a> {
    declarations: &'a Declarations,
    done: &'a Final,
    initial: &'a State,
    /// Where binbun continues.
    next: &'a Term,
}

/// A difference: its label, the Boolean that it holds, the two values it
/// compares (binbun's, Sail's) if it compares values, and the address it
/// compares at if it compares memory.
type Difference = (String, Term, Option<(Term, Term)>, Option<Term>);

fn differences(script: &mut Script, ends: &Ends<'_>, trace: &Trace) -> Vec<Difference> {
    let Ends {
        declarations,
        done,
        initial,
        next,
    } = *ends;
    if trace.exception.is_some() {
        return exception_differences(done, trace);
    }
    let sail_next = script.name(
        "sail.next",
        &smt::sort(64),
        Term::new(trace.next_pc.clone()),
    );
    let mut differences: Vec<Difference> = vec![
        ("trap".into(), done.trap.clone(), None, None),
        ("system call".into(), done.system_call.clone(), None, None),
        ("loop bound".into(), done.exhausted.clone(), None, None),
        (
            "next pc".into(),
            smt::not(&smt::eq(next, &sail_next)),
            Some((next.clone(), sail_next)),
            None,
        ),
    ];
    for ((info, binbun), start) in declarations
        .registers
        .iter()
        .zip(&done.state.registers)
        .zip(&initial.registers)
    {
        if context::location(info.name) == Some(context::Location::ProgramCounter) {
            let label = "pc register written".to_owned();
            differences.push((label, smt::not(&smt::eq(binbun, start)), None, None));
            continue;
        }
        let sail = match info.name {
            "btype" => trace
                .writes
                .get("btype")
                .or(trace.btype_next.as_ref())
                .map_or_else(
                    || smt::literal(info.width, 0),
                    |value| Term::new(value.clone()),
                ),
            name => trace
                .writes
                .get(name)
                .map_or_else(|| start.clone(), |value| Term::new(value.clone())),
        };
        let sail = script.name("sail", &smt::sort(info.width), sail);
        let differs = smt::not(&smt::eq(binbun, &sail));
        let label = info.name.to_owned();
        differences.push((label, differs, Some((binbun.clone(), sail)), None));
    }
    let cell = script.declare("cell", &smt::sort(64));
    let binbun_byte = script.name(
        "cell.binbun",
        &smt::sort(8),
        select(&done.state.memory, &cell),
    );
    let sail_byte = script.name(
        "cell.sail",
        &smt::sort(8),
        select(&Term::new(trace.memory.clone()), &cell),
    );
    differences.push((
        "memory".into(),
        smt::not(&smt::eq(&binbun_byte, &sail_byte)),
        Some((binbun_byte, sail_byte)),
        Some(cell),
    ));
    let probe = script.declare("probe", &smt::sort(64));
    for (label, binbun, sail) in [
        ("bytes read", &done.loads, &trace.loads),
        ("bytes written", &done.stores, &trace.stores),
    ] {
        let binbun = script.name("touch.binbun", "Bool", smt::touches(binbun, &probe, 64));
        let sail = smt::or(
            &sail
                .iter()
                .map(|(address, bytes)| {
                    Term::new(format!(
                        "(bvule (bvsub {probe} {address}) {})",
                        smt::literal(64, u64::from(bytes.saturating_sub(1)))
                    ))
                })
                .collect::<Vec<_>>(),
        );
        let sail = script.name("touch.sail", "Bool", sail);
        let differs = smt::not(&smt::eq(&binbun, &sail));
        differences.push((
            label.into(),
            differs,
            Some((binbun, sail)),
            Some(probe.clone()),
        ));
    }
    differences
}

fn select(memory: &Term, address: &Term) -> Term {
    Term::new(format!("(select {memory} {address})"))
}

/// The exception class of an SVC (`ESR_ELx.EC`).
const SUPERVISOR_CALL: u64 = 0x15;

/// On a path that takes an exception: binbun must trap, or for a
/// supervisor call enter the system without trapping.
fn exception_differences(done: &Final, trace: &Trace) -> Vec<Difference> {
    if trace.exception.as_ref().and_then(trace::Exception::class) == Some(SUPERVISOR_CALL) {
        return vec![
            ("trap".into(), done.trap.clone(), None, None),
            (
                "no system call".into(),
                smt::not(&done.system_call),
                None,
                None,
            ),
        ];
    }
    vec![("no trap".into(), smt::not(&done.trap), None, None)]
}

/// Ties the results of the path's `binbun_<intrinsic>` calls to binbun's
/// intrinsic of that name on the same arguments (the uninterpreted function
/// `binbun_semantics::smt` declares for its output 0).
fn link_intrinsics(
    script: &mut Script,
    declarations: &Declarations,
    trace: &mut Trace,
) -> Result<(), String> {
    for (name, args, result) in &trace.intrinsics {
        let info = declarations
            .find_intrinsic(name)
            .and_then(|id| declarations.intrinsic(id))
            .ok_or_else(|| format!("binbun declares no intrinsic {name}"))?;
        let [width] = info.outputs else {
            return Err(format!("the intrinsic {name} has not one output"));
        };
        if info.inputs.len() != args.len() {
            return Err(format!("Sail calls {name} with {} arguments", args.len()));
        }
        let sorts: Vec<String> = info.inputs.iter().map(|&width| smt::sort(width)).collect();
        let function =
            script.declare_function(&format!("intrinsic.{name}.0"), &sorts, &smt::sort(*width));
        let application = if args.is_empty() {
            function.as_str().to_owned()
        } else {
            format!("({function} {})", args.join(" "))
        };
        trace.links.push(format!("(= {result} {application})"));
    }
    Ok(())
}

/// Emits one path's queries: feasibility, then a difference.
fn query(script: &mut Script, ends: &Ends<'_>, trace: &Trace) -> Query {
    script.push();
    for command in &trace.commands {
        script.command(command);
    }
    for link in &trace.links {
        script.assert(&Term::new(link.clone()));
    }
    script.command("(check-sat)");
    let differences = differences(script, ends, trace);
    let mut labels = Vec::new();
    let mut flags = Vec::new();
    let mut values = Vec::new();
    let mut addresses = Vec::new();
    for (index, (label, differs, compared, address)) in differences.into_iter().enumerate() {
        flags.push(script.define(&format!("differs.{index}"), "Bool", &differs));
        if let Some((binbun, sail)) = compared {
            values.push((label.clone(), binbun, sail));
        }
        if let Some(address) = address {
            addresses.push((label.clone(), address));
        }
        labels.push(label);
    }
    script.assert(&smt::or(&flags));
    script.command("(check-sat)");
    for flag in &flags {
        script.command(&format!("(get-value ({flag}))"));
    }
    let inputs: Vec<String> = ends
        .declarations
        .registers
        .iter()
        .map(|info| info.name.to_owned())
        .filter(|name| trace.reads.contains(name))
        .collect();
    for name in &inputs {
        script.command(&format!(
            "(get-value ({}))",
            smt::symbol(&format!("s.{name}"))
        ));
    }
    for (_, binbun, sail) in &values {
        script.command(&format!("(get-value ({binbun}))"));
        script.command(&format!("(get-value ({sail}))"));
    }
    for (_, address) in &addresses {
        script.command(&format!("(get-value ({address}))"));
    }
    script.command("(echo \"@@\")");
    script.pop();
    let exception = trace
        .exception
        .as_ref()
        .map(|exception| match exception.class() {
            Some(class) => format!("{}, EC {class:#x}", exception.register),
            None => exception.register.clone(),
        });
    Query {
        exception,
        labels,
        inputs,
        values,
        addresses,
    }
}

/// Reads z3's answers to the queries.
fn answers(output: &str, queries: &[Query]) -> Result<Verdict, String> {
    let items = solver::items(output);
    let mut items = items.iter().map(String::as_str);
    let mut exceptions = 0;
    for (path, query) in queries.iter().enumerate() {
        match items.next() {
            Some("sat") => {}
            Some("unsat") => {
                return Err(format!(
                    "path {path} is infeasible once tied to binbun's state (a mapping bug)"
                ));
            }
            other => return Err(format!("z3 on path {path}'s feasibility: {other:?}")),
        }
        let differs = match items.next() {
            Some("unsat") => false,
            Some("sat") => true,
            other => return Err(format!("z3 on path {path}: {other:?}")),
        };
        let mut answers = Vec::new();
        for item in items.by_ref() {
            if item == "@@" {
                break;
            }
            answers.push(item);
        }
        if differs {
            return Ok(Verdict::Counterexample(counterexample(
                path, query, &answers,
            )));
        }
        exceptions += usize::from(query.exception.is_some());
    }
    Ok(Verdict::Equivalent {
        paths: queries.len(),
        exceptions,
    })
}

fn counterexample(path: usize, query: &Query, answers: &[&str]) -> Counterexample {
    let mut answers = answers
        .iter()
        .map(|item| solver::value(item).unwrap_or(item));
    let differences: Vec<String> = query
        .labels
        .iter()
        .zip(answers.by_ref())
        .filter(|(_, value)| *value == "true")
        .map(|(label, _)| label.clone())
        .collect();
    let inputs = query
        .inputs
        .iter()
        .zip(answers.by_ref())
        .map(|(name, value)| (name.clone(), value.to_owned()))
        .collect();
    let mut values = Vec::new();
    for (label, _, _) in &query.values {
        let binbun = answers.next().unwrap_or("?").to_owned();
        let sail = answers.next().unwrap_or("?").to_owned();
        if differences.contains(label) {
            values.push((label.clone(), binbun, sail));
        }
    }
    let mut addresses = Vec::new();
    for (label, _) in &query.addresses {
        let address = answers.next().unwrap_or("?").to_owned();
        if differences.contains(label) {
            addresses.push((label.clone(), address));
        }
    }
    Counterexample {
        path,
        exception: query.exception.clone(),
        differences,
        inputs,
        values,
        addresses,
    }
}
