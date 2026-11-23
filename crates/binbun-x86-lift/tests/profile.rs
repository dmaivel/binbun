//! Processor profiles: what this processor does where L0 leaves a value
//! undefined, measured site by site through the CPU oracle
//! (`tools/cpu-oracle`), as the hardware test runs instructions, and
//! written as a profile.
//!
//! ```sh
//! sh scripts/cpu-oracle.sh
//! BINBUN_CPU_ORACLE=$PWD/target/cpu-oracle BINBUN_PROFILE_OUT=raptor.toml \
//!   taskset -c 0-15 cargo test --release -p binbun-x86-lift --test profile \
//!   -- --ignored --nocapture
//! ```
//!
//! - The allowed CPUs must be one core type (the P-cores, 0-15 on the
//!   i9-14900F, or the E-cores, 16-31); the profile is named after it
//!   (CPUID leaves 1 and 1AH, read through the oracle).
//! - `BINBUN_PROFILE_SITES`: `all` (default), `corpus` (every site of a
//!   form that the files of `BINBUN_PROFILE_CORPUS`, colon-separated,
//!   contain), or site names, comma-separated.
//! - `BINBUN_PROFILE_SEED`, `BINBUN_PROFILE_PER_FORM` (encodings per form
//!   and operand width, default 4), `BINBUN_PROFILE_STATES` (random states
//!   per encoding, default 48), `BINBUN_PROFILE_OUT` (the file written),
//!   `BINBUN_PROFILE_REVISION` (its revision, default 1: a new one when
//!   rules change), `BINBUN_PROFILE_REPORT` (each site's observations that
//!   no candidate explains, with the closest candidates and what refutes
//!   them, and L0's disagreements).
//!
//! Each site's forms run from systematic states (every count from 0 to 71,
//! operands from a list of edge values, both values of each flag) and
//! random ones (the hardware test's); where the site's output is undefined
//! after L0 ran, the processor's bits there are an observation, with the
//! inputs' values. Every candidate of a library built from the site's
//! inputs is checked against every observation; z3 is asked for a state
//! separating any two survivors (and the survivor from its closest
//! rivals), which runs on the processor too, until one survives or the
//! rest are proved equal on the forms measured. A rule is credible when it
//! is the only survivor after the systematic states, at least 1,000 random
//! observations and every separating state; else `unknown`, or `varies`
//! where one state gave two answers.
//!
//! z3 has a resource limit per query (`Z3_RLIMIT`), not a time limit, so
//! the same seed gives the same profile however busy the machine is; the
//! run ends with the most any query took. A wall-clock safety net far
//! beyond it fails the run.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

#[allow(dead_code, reason = "shared with the other tests")]
mod support;

#[allow(dead_code, reason = "shared with the hardware test")]
#[path = "support/cpu.rs"]
mod cpu;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use binbun_semantics::Semantics;
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{self, Machine, Outcome, Value};
use binbun_semantics::ir::{Expr, ExprId, RegisterId, SiteId};
use binbun_semantics::profile::Profile;
use binbun_semantics::rule::{Compiled, Rule};
use binbun_semantics::smt::{self, Options, Script, Term};
use binbun_x86::{Flag, Form, Instruction, Mode, OperandName, Value as OperandValue};
use binbun_x86_lift::profiles::{self, site_table_hash};
use binbun_x86_lift::registers::{self, C0, FPR0, RAX};
use binbun_x86_lift::site::Output;
use binbun_x86_lift::sites::SITES;
use binbun_x86_lift::{X86, lift};

use cpu::{Answer, CONDITION_BITS, FLAGS, FpState, GPRS, Oracle, Random, Start, Test};

/// Operand values the systematic states take, in turn.
const EDGES: [u64; 24] = [
    0,
    1,
    2,
    3,
    u64::MAX,
    1 << 63,
    (1 << 63) - 1,
    0x8000_0000,
    0x7fff_ffff,
    0xffff_ffff,
    0x8000,
    0x7fff,
    0xffff,
    0x80,
    0x7f,
    0xff,
    0x8f,
    0x47_8000_0000,
    0x100,
    0x5555_5555_5555_5555,
    0xaaaa_aaaa_aaaa_aaaa,
    0x8000_0000_0000_0001,
    0x0123_4567_89ab_cdef,
    0x10,
];

/// Systematic states per encoding: counts 0 to 71 in `cl`.
const SYSTEMATIC: u64 = 72;

/// Random observations a credible rule needs.
const RANDOM_NEEDED: usize = 1000;

/// One state of one encoding: what ran, and from where.
#[derive(Clone)]
struct Case {
    bytes: Vec<u8>,
    instruction: Instruction,
    start: Start,
    seeds: BTreeMap<u64, u8>,
    random: bool,
}

/// One site's value seen on the processor: its inputs (from L0) and the
/// bits the processor left where L0's output is undefined.
#[derive(Clone)]
struct Observation {
    inputs: Vec<Value>,
    cpu: Bits,
    random: bool,
    /// The case, for z3 (the first few per input widths).
    case: Option<usize>,
}

/// What one case gave.
#[derive(Default)]
struct Ran {
    observations: Vec<(SiteId, Vec<Value>, Bits)>,
    /// L0 disagrees with the processor on a defined bit.
    disagrees: Option<String>,
}

/// Everything seen per site.
#[derive(Default)]
struct Seen {
    observations: Vec<Observation>,
    varies: bool,
}

/// The CPUs this process may run on.
fn allowed_cpus() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .unwrap()
        .trim()
        .to_owned()
}

/// The registers of `instruction`'s memory operands' addresses (and the
/// stack pointer): fixed when z3 chooses a state.
fn address_registers(instruction: &Instruction) -> BTreeSet<usize> {
    let mut fixed = BTreeSet::from([4]);
    for operand in instruction.operands() {
        let OperandValue::Memory(memory) = operand.value else {
            continue;
        };
        if operand.name == OperandName::Agen {
            continue;
        }
        for register in [memory.base, memory.index].into_iter().flatten() {
            if let Some(view) = registers::gpr(register) {
                fixed.insert(usize::from(view.register.0 - RAX.0));
            }
        }
    }
    fixed
}

/// The addresses of `instruction`'s explicit memory operands in a state
/// with `gprs` (64-bit addressing, no segment base).
fn targets(instruction: &Instruction, gprs: &[u64; 16]) -> Vec<u64> {
    let value = |register| {
        registers::gpr(register).map_or(0, |view| {
            let full = gprs[usize::from(view.register.0 - RAX.0)];
            if view.width >= 64 {
                full
            } else {
                (full >> view.offset) & ((1 << view.width) - 1)
            }
        })
    };
    let mut out = Vec::new();
    for operand in instruction.operands() {
        let OperandValue::Memory(memory) = operand.value else {
            continue;
        };
        if operand.name == OperandName::Agen || memory.segment.is_some() {
            continue;
        }
        let mut address = memory.displacement.cast_unsigned();
        if let Some(base) = memory.base {
            address = address.wrapping_add(value(base));
        }
        if let Some(index) = memory.index {
            address =
                address.wrapping_add(value(index).wrapping_mul(u64::from(memory.scale.max(1))));
        }
        if instruction.address_width() == 32 {
            address &= 0xffff_ffff;
        }
        out.push(address);
    }
    out
}

/// Systematic state `i` of `instruction`: memory bases as in a random
/// state, every other register an edge value, `cl` the count `i`, flags
/// alternating, memory operands edge values too.
fn systematic(
    instruction: &Instruction,
    i: u64,
    random: &mut Random,
) -> (Start, BTreeMap<u64, u8>) {
    let (mut gprs, _) = cpu::state(instruction, random);
    let fixed = address_registers(instruction);
    for (j, slot) in gprs.iter_mut().enumerate() {
        if fixed.contains(&j) {
            continue;
        }
        let pick = usize::try_from((i / 2 + 5 * j as u64) % EDGES.len() as u64).unwrap();
        *slot = EDGES[pick];
    }
    if !fixed.contains(&1) {
        gprs[1] = (gprs[1] & !0xff) | i;
    }
    let bits = (i.wrapping_mul(0x9e37_79b9) >> 7) ^ i;
    let rflags = 0x2 | (bits & 0x8d5) | (i & 1) | (((i >> 1) & 1) << 11);
    let mut seeds = BTreeMap::new();
    for (k, address) in targets(instruction, &gprs).into_iter().enumerate() {
        let low = EDGES[usize::try_from((i + 7 * k as u64) % EDGES.len() as u64).unwrap()];
        let high = EDGES[usize::try_from((i + 11 + 3 * k as u64) % EDGES.len() as u64).unwrap()];
        for (at, byte) in (address..).zip(low.to_le_bytes().into_iter().chain(high.to_le_bytes())) {
            seeds.insert(at, byte);
        }
    }
    let fp = cpu::uses_fp(instruction).then(|| FpState::random(random));
    let code = cpu::CODE + random.below(1 << 20) * cpu::PAGE + random.below(cpu::PAGE - 16);
    (
        Start {
            code,
            gprs,
            rflags,
            fp,
        },
        seeds,
    )
}

/// A random state of `instruction`, as the hardware test makes them.
fn random_case(instruction: &Instruction, random: &mut Random) -> (Start, BTreeMap<u64, u8>) {
    let code = cpu::CODE + random.below(1 << 20) * cpu::PAGE + random.below(cpu::PAGE - 16);
    let (gprs, seeds) = cpu::state(instruction, random);
    let rflags = (random.next() & 0xcd5) | 0x2;
    let fp = cpu::uses_fp(instruction).then(|| FpState::random(random));
    (
        Start {
            code,
            gprs,
            rflags,
            fp,
        },
        seeds,
    )
}

/// Bits `mask` selects of `cpu`, packed from bit 0 (`None` past 128).
fn packed(cpu: &[u8], mask: &[u8]) -> Option<(u32, u128)> {
    let (mut count, mut value) = (0u32, 0u128);
    for (&byte, &bits) in cpu.iter().zip(mask) {
        for bit in 0..8 {
            if bits >> bit & 1 == 1 {
                if count >= 128 {
                    return None;
                }
                value |= u128::from(byte >> bit & 1) << count;
                count += 1;
            }
        }
    }
    Some((count, value))
}

/// The processor's bits where `site`'s output is undefined after L0 ran:
/// as many as the site's value has, or `None`.
fn observed(
    site: SiteId,
    instruction: &Instruction,
    machine: &mut Test,
    answer: &Answer,
    width: u16,
) -> Option<Bits> {
    let info = SITES.get(usize::from(site.0))?;
    let gpr = |machine: &mut Test, id: RegisterId| {
        let index = usize::from(id.0.checked_sub(RAX.0)?);
        let name = GPRS.get(index)?;
        let value = machine.read(id);
        let cpu = answer.values.get(*name).copied().unwrap_or(0);
        Some((
            cpu.to_le_bytes().to_vec(),
            value.undefined.low_u64().to_le_bytes().to_vec(),
        ))
    };
    let memory = |machine: &mut Test| {
        let (mut cpu, mut mask) = (Vec::new(), Vec::new());
        for (address, &undefined) in &machine.undefined {
            if undefined != 0 {
                cpu.push(answer.memory.get(address).copied().unwrap_or(0));
                mask.push(undefined);
            }
        }
        Some((cpu, mask))
    };
    let (cpu, mask) = match info.output {
        Output::Flag(flag) => {
            let id = registers::flag(flag)?;
            if machine.read(id).is_defined() {
                return None;
            }
            let bit = match flag {
                Flag::Fc0 | Flag::Fc1 | Flag::Fc2 | Flag::Fc3 => {
                    let index = usize::from(id.0 - C0.0);
                    (answer.values.get("fsw").copied().unwrap_or(0) >> CONDITION_BITS[index]) & 1
                }
                Flag::Cf
                | Flag::Pf
                | Flag::Af
                | Flag::Zf
                | Flag::Sf
                | Flag::Tf
                | Flag::If
                | Flag::Df
                | Flag::Of
                | Flag::Iopl
                | Flag::Nt
                | Flag::Rf
                | Flag::Vm
                | Flag::Ac
                | Flag::Vif
                | Flag::Vip
                | Flag::Id => {
                    let name = X86.info(id)?.name;
                    let (_, bit) = FLAGS.iter().find(|(flag, _)| *flag == name)?;
                    (answer.values.get("rflags").copied().unwrap_or(0) >> bit) & 1
                }
            };
            return Some(Bits::from_u64(1, bit));
        }
        Output::Register(register) => gpr(machine, registers::gpr(register)?.register)?,
        Output::Operand(n) => match instruction.operands().nth(usize::from(n))?.value {
            OperandValue::Register(Some(register)) => {
                gpr(machine, registers::gpr(register)?.register)?
            }
            OperandValue::Memory(_) => memory(machine)?,
            OperandValue::Register(None)
            | OperandValue::Immediate { .. }
            | OperandValue::SecondImmediate(_)
            | OperandValue::Relative(_)
            | OperandValue::Field(_) => return None,
        },
        Output::Memory => memory(machine)?,
    };
    let (count, value) = packed(&cpu, &mask)?;
    (count == u32::from(width)).then(|| Bits::from_u128(width, value))
}

/// Runs `case` in L0 and on the processor: each site evaluated once whose
/// output L0 leaves undefined, with what the processor put there.
fn run_case(oracle: &mut Oracle, case: &Case, random: &mut Random) -> Ran {
    let Ok(semantics) = lift(&case.instruction, Mode::Bits64, case.start.code) else {
        return Ran::default();
    };
    let mut machine = case.start.machine(&case.bytes, &case.seeds, random);
    let outcome = interpret::run(&semantics, &mut machine);
    // Not run on the processor: undetermined, a system call, skipped.
    if matches!(outcome, Outcome::Undetermined | Outcome::SystemCall) {
        return Ran::default();
    }
    let line = case.start.line(&case.bytes, &machine.initial);
    let answer = cpu::parse(&oracle.ask(&line));
    if answer.kind == "skip" {
        return Ran::default();
    }
    let code = case.start.code;
    let next = code + case.bytes.len() as u64;
    let mut wrong = Vec::new();
    match cpu::resumes_at(outcome, &answer, code, next) {
        Some(rip) => {
            cpu::compare(&mut machine, &answer, rip, &mut wrong);
            if case.start.fp.is_some() {
                let fault = outcome == Outcome::Trap(binbun_semantics::ir::Trap::FloatingPoint);
                cpu::compare_fp(&mut machine, &answer, fault, &mut wrong);
            }
        }
        None => wrong.push(format!("L0 {outcome:?}, CPU {}", answer.kind)),
    }
    if !wrong.is_empty() {
        let text = case.instruction.intel(code).to_string();
        return Ran {
            disagrees: Some(format!("`{text}`\n  {line}\n  {}", wrong.join("\n  "))),
            ..Ran::default()
        };
    }
    // Each site once, and alone at its output. A site evaluated again on
    // the same inputs (an undefined value an expression repeats: SHL's
    // CF in its OF's unchosen arm) is the one value.
    let mut records = std::mem::take(&mut machine.sites);
    let mut kept = Vec::with_capacity(records.len());
    for record in records.drain(..) {
        if !kept.contains(&record) {
            kept.push(record);
        }
    }
    let records = kept;
    let mut counts: HashMap<SiteId, usize> = HashMap::new();
    for (site, _) in &records {
        *counts.entry(*site).or_default() += 1;
    }
    let output = |site: SiteId| SITES.get(usize::from(site.0)).map(|info| info.output);
    let mut observations = Vec::new();
    for (site, inputs) in records {
        let shared = counts
            .keys()
            .any(|&other| other != site && output(other) == output(site));
        if counts[&site] != 1 || shared {
            continue;
        }
        let width = width_of(&semantics, site).unwrap_or(1);
        if let Some(cpu) = observed(site, &case.instruction, &mut machine, &answer, width) {
            observations.push((site, inputs, cpu));
        }
    }
    Ran {
        observations,
        ..Ran::default()
    }
}

/// The width of `site`'s undefined value in `semantics`.
fn width_of(semantics: &Semantics, site: SiteId) -> Option<u16> {
    let serial = semantics
        .sites
        .iter()
        .find(|use_| use_.site == site)?
        .serial;
    semantics.exprs.iter().find_map(|&(expr, width)| {
        matches!(expr, Expr::Undefined { serial: own, .. } if own == serial).then_some(width)
    })
}

/// The candidate rules for a site with inputs `names` of `widths`, giving
/// `width` bits, simplest first.
fn library(names: &[&str], widths: &[u16], width: u16) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let osz = widths.first().copied().unwrap_or(0);
    if width == 1 {
        let mut atoms: Vec<(String, bool)> = Vec::new();
        for (&name, &w) in names.iter().zip(widths) {
            let count = name == "count";
            if w == 1 {
                atoms.push((name.to_owned(), count));
                continue;
            }
            for atom in [
                format!("msb({name})"),
                format!("bit({name}, 0)"),
                format!("bit({name}, 1)"),
                format!("bit({name}, 4)"),
            ] {
                atoms.push((atom, count));
            }
            if w == osz && w > 2 {
                atoms.push((format!("bit({name}, osz - 2)"), count));
            }
            if w > osz {
                // A double-width product's low half (MUL r/m8's AX).
                atoms.push((format!("bit({name}, osz - 1)"), count));
                atoms.push((format!("(trunc({name}, osz) == 0)"), count));
            }
            if w >= 8 {
                atoms.push((format!("parity8({name})"), count));
            }
            atoms.push((format!("({name} == 0)"), count));
        }
        out.extend(["0", "1"].map(str::to_owned));
        out.extend(atoms.iter().map(|(atom, _)| atom.clone()));
        out.extend(atoms.iter().map(|(atom, _)| format!("{atom} ^ 1")));
        for (i, (a, _)) in atoms.iter().enumerate() {
            for (b, _) in atoms.iter().skip(i + 1) {
                out.push(format!("{a} ^ {b}"));
            }
        }
        if names.contains(&"count") {
            for (atom, count) in &atoms {
                if *count {
                    continue;
                }
                for mask in [31, 63] {
                    out.push(format!(
                        "if (count & {mask}) == osz {{ {atom} }} else {{ 0 }}"
                    ));
                }
            }
        }
        if names.contains(&"count") && names.contains(&"old") {
            rotate_stays(&atoms, &mut out);
        }
        for (&name, &w) in names.iter().zip(widths) {
            if w == 1 || name.starts_with("defined.") || name == "old" || name == "count" {
                continue;
            }
            for (atom, _) in atoms.iter().filter(|(atom, _)| atom.contains("defined.")) {
                for constant in [0, 1] {
                    out.push(format!("if {name} == 0 {{ {constant} }} else {{ {atom} }}"));
                }
            }
        }
    } else {
        out.extend(["0", "!0"].map(str::to_owned));
        for (&name, &w) in names.iter().zip(widths) {
            match w.cmp(&width) {
                std::cmp::Ordering::Equal => out.push(name.to_owned()),
                std::cmp::Ordering::Greater => {
                    for k in 0..w / width {
                        out.push(format!("bits({name}, {}, {width})", k * width));
                    }
                }
                std::cmp::Ordering::Less => out.push(format!("zext({name}, {width})")),
            }
        }
        let has = |wanted: &str| names.contains(&wanted);
        if has("dst") && has("src") && has("count") && width == 16 {
            // SHLD and SHRD past 16: the result of a 48-bit shift.
            let three = |high: &str, middle: &str, low: &str| {
                format!("(zext({high}, 64) << 32 | zext({middle}, 64) << 16 | zext({low}, 64))")
            };
            for (high, middle, low) in [
                ("dst", "src", "dst"),
                ("dst", "src", "src"),
                ("src", "src", "dst"),
            ] {
                let x = three(high, middle, low);
                out.push(format!("trunc({x} >> (32 - (count & 31)), 16)"));
                out.push(format!("trunc({x} >> (count & 31), 16)"));
            }
        }
    }
    let mut seen = BTreeSet::new();
    out.retain(|text| seen.insert(text.clone()));
    out
}

/// The candidates of a rotate's flag, from `atoms` (each with whether it
/// reads the count): a rotate by a multiple of its period (`rcl r/m8, 9`:
/// osz + 1 through the carry, osz without) moves nothing, and the flag
/// may stay. Only 8- and 16-bit operands have such masked counts.
fn rotate_stays(atoms: &[(String, bool)], out: &mut Vec<String>) {
    let arms: Vec<&str> = atoms
        .iter()
        .filter(|(_, count)| !count)
        .map(|(atom, _)| atom.as_str())
        .collect();
    let mut pairs: Vec<String> = arms.iter().map(|&arm| arm.to_owned()).collect();
    for (i, a) in arms.iter().enumerate() {
        for b in arms.iter().skip(i + 1) {
            pairs.push(format!("{a} ^ {b}"));
        }
    }
    let mut stays: Vec<String> = ["osz + 1", "osz"]
        .map(|period| {
            format!(
                "((count & 31) == {period}) | ((count & 31) == {period} + {period}) | ((count & 31) == {period} + {period} + {period})"
            )
        })
        .to_vec();
    // Or the count has bits the mask drops.
    stays.extend(["(count & 31) != count", "(count & 63) != count"].map(str::to_owned));
    for stay in &stays {
        for arm in &pairs {
            out.push(format!("if {stay} {{ old }} else {{ {arm} }}"));
        }
    }
}

/// A candidate's verdict on the observations so far.
#[derive(Clone, Default)]
struct Verdict {
    refuted: usize,
    judged: usize,
}

/// One candidate, made per input widths.
struct Candidate {
    text: String,
    rule: Rule,
    made: HashMap<(Vec<u16>, u16), Option<Compiled>>,
    verdict: Verdict,
}

impl Candidate {
    fn new(text: String, names: &[&str]) -> Option<Self> {
        let rule = Rule::parse(&text, names).ok()?;
        Some(Self {
            text,
            rule,
            made: HashMap::new(),
            verdict: Verdict::default(),
        })
    }

    /// What it gives on `observation`'s inputs: `Err` where it cannot be
    /// made or evaluated for their widths, `Ok(None)` where it is unknown.
    fn predict(&mut self, observation: &Observation) -> Result<Option<Bits>, ()> {
        let widths: Vec<u16> = observation.inputs.iter().map(Value::width).collect();
        let width = observation.cpu.width();
        let rule = &self.rule;
        let compiled = self
            .made
            .entry((widths.clone(), width))
            .or_insert_with(|| rule.instantiate(&widths, width).ok());
        let compiled = compiled.as_ref().ok_or(())?;
        let value = compiled.eval(&observation.inputs).map_err(|_| ())?;
        Ok(value.known())
    }

    /// Whether `observation` refutes it: `None` where it cannot say (an
    /// input unknown, and so its value).
    fn refuted_by(&mut self, observation: &Observation) -> Option<bool> {
        let unknown_input = observation.inputs.iter().any(|input| !input.is_defined());
        match self.predict(observation) {
            Ok(Some(bits)) => Some(bits != observation.cpu),
            Ok(None) if unknown_input => None,
            Ok(None) | Err(()) => Some(true),
        }
    }

    /// Checks one observation; `true` if it refutes the candidate.
    fn check(&mut self, observation: &Observation) -> bool {
        match self.refuted_by(observation) {
            Some(true) => {
                self.verdict.refuted += 1;
                true
            }
            Some(false) => {
                self.verdict.judged += 1;
                false
            }
            None => false,
        }
    }

    fn alive(&self) -> bool {
        self.verdict.refuted == 0 && self.verdict.judged > 0
    }
}

/// z3's resource limit per query (its `rlimit`, counted in its own steps):
/// unlike a time limit it does not depend on the machine's load, so the
/// same measurement gives the same rules and credibility. The hardest query
/// of a full measurement (z3 4.16, either core type) takes 1,246,211:
/// proving two of IDIV's flag rules equal, 5 seconds on an idle P-core and 9
/// on an E-core. The limit is eight times that; the count is z3's own, so
/// another z3 version may need it measured again.
const Z3_RLIMIT: u64 = 10_000_000;

/// A safety net in wall-clock seconds, far beyond what the resource limit
/// allows even on a loaded machine: reaching it fails the measurement.
const Z3_SECONDS: u64 = 1800;

/// The most resources one z3 query took so far.
static Z3_HARDEST: AtomicU64 = AtomicU64::new(0);

/// What z3 answered to `script`'s `check-sat`.
struct Answers {
    /// The output lines: the `check-sat` answer, then the `get-value`s.
    lines: Vec<String>,
    /// It stopped at its resource limit (`unknown` for that reason).
    exhausted: bool,
}

/// Runs z3 on `script` (one `check-sat`) under the resource limit `rlimit`
/// ([`Z3_RLIMIT`] in a measurement); panics if it reaches the wall-clock
/// safety net or dies.
fn z3(script: &str, rlimit: u64) -> Answers {
    let mut child = Command::new("z3")
        .args([
            "-in".to_owned(),
            "-smt2".to_owned(),
            format!("-T:{Z3_SECONDS}"),
            format!("rlimit={rlimit}"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("z3 on the PATH");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(script.as_bytes()).unwrap();
    stdin
        .write_all(b"(get-info :reason-unknown)\n(get-info :rlimit)\n")
        .unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    let mut lines: Vec<String> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert!(
        !lines.iter().any(|line| line == "timeout"),
        "z3 ran past its {Z3_SECONDS}-second safety net (the resource limit is {rlimit})"
    );
    assert!(output.status.code().is_some(), "z3 died: {}", output.status);
    let used = lines
        .pop()
        .as_deref()
        .and_then(|line| {
            line.strip_prefix("(:rlimit ")?
                .strip_suffix(')')?
                .parse()
                .ok()
        })
        .expect("z3's resource count");
    Z3_HARDEST.fetch_max(used, Ordering::Relaxed);
    let reason = lines.pop().unwrap_or_default();
    let exhausted =
        lines.first().is_some_and(|line| line == "unknown") && reason.contains("resource limit");
    Answers { lines, exhausted }
}

/// `semantics` with `site`'s undefined value replaced by `rule`, or `None`
/// if the rule does not fit.
fn substituted(semantics: &Semantics, site: SiteId, rule: &Rule) -> Option<Semantics> {
    let position = semantics.sites.iter().position(|use_| use_.site == site)?;
    let use_ = &semantics.sites[position];
    let at = semantics.exprs.iter().position(
        |&(expr, _)| matches!(expr, Expr::Undefined { serial, .. } if serial == use_.serial),
    )?;
    let widths: Vec<u16> = use_.inputs.iter().map(|&id| semantics.width(id)).collect();
    let compiled = rule.instantiate(&widths, semantics.exprs[at].1).ok()?;
    let mut exprs = semantics.exprs[..at].to_vec();
    let value = compiled.emit(&mut exprs, &use_.inputs);
    let base = u32::try_from(exprs.len()).unwrap();
    let at = u32::try_from(at).unwrap();
    let map = |id: ExprId| match id.0.cmp(&at) {
        std::cmp::Ordering::Less => id,
        std::cmp::Ordering::Equal => value,
        std::cmp::Ordering::Greater => ExprId(base + id.0 - at - 1),
    };
    for &(expr, width) in &semantics.exprs[at as usize + 1..] {
        exprs.push((expr.map_operands(&mut |id| map(id)), width));
    }
    let mut body = semantics.body.clone();
    for stmt in &mut body {
        stmt.map_exprs(&mut |id| map(id));
    }
    let mut sites = semantics.sites.clone();
    sites.remove(position);
    for other in &mut sites {
        for input in &mut other.inputs {
            *input = map(*input);
        }
    }
    Some(Semantics {
        exprs,
        locals: semantics.locals.clone(),
        body,
        sites,
    })
}

/// The registers z3 may choose in a case of `instruction`: the general
/// registers not used for addresses, the status flags, the x87 condition
/// codes and registers.
fn free_registers(instruction: &Instruction) -> Vec<RegisterId> {
    let fixed = address_registers(instruction);
    let mut free: Vec<RegisterId> = (0..16u16)
        .filter(|i| !fixed.contains(&usize::from(*i)))
        .map(|i| RegisterId(RAX.0 + i))
        .collect();
    for name in ["cf", "pf", "af", "zf", "sf", "of"] {
        free.push(X86.find(name).unwrap());
    }
    free.extend((0..4).map(|i| RegisterId(C0.0 + i)));
    free.extend((0..8).map(|i| RegisterId(FPR0.0 + i)));
    free
}

/// What z3 says about two rules at `site` in `case`.
enum Separation {
    /// A state where they differ.
    State(Box<Case>),
    /// They never differ here.
    Equal,
    /// No answer within z3's resource limit.
    Exhausted,
    /// No answer (an output z3 cannot compare).
    Unknown,
}

/// Asks z3 for a state of `case`'s instruction (its addresses as in
/// `case`) where `a` and `b` give `site` different outputs.
#[expect(clippy::too_many_lines, reason = "one z3 query, built in order")]
fn separate(case: &Case, site: SiteId, a: &Rule, b: &Rule) -> Separation {
    let Ok(semantics) = lift(&case.instruction, Mode::Bits64, case.start.code) else {
        return Separation::Unknown;
    };
    let (Some(one), Some(two)) = (
        substituted(&semantics, site, a),
        substituted(&semantics, site, b),
    ) else {
        return Separation::Unknown;
    };
    let output = match SITES[usize::from(site.0)].output {
        Output::Flag(flag) => registers::flag(flag),
        Output::Register(register) => registers::gpr(register).map(|view| view.register),
        Output::Operand(n) => {
            if let Some(OperandValue::Register(Some(register))) = case
                .instruction
                .operands()
                .nth(usize::from(n))
                .map(|o| o.value)
            {
                registers::gpr(register).map(|view| view.register)
            } else {
                None
            }
        }
        Output::Memory => None,
    };
    let Some(output) = output else {
        return Separation::Unknown;
    };
    let options = Options::default();
    let mut script = Script::new();
    let initial = script.initial_state(&X86, "s.", &options);
    let mut random = Random(0x1234_5678 | 1);
    let template = case.start.machine(&case.bytes, &case.seeds, &mut random);
    let free = free_registers(&case.instruction);
    for (&id, value) in &template.registers {
        if free.contains(&id) || !value.is_defined() {
            continue;
        }
        let term = initial.register(id).unwrap();
        script.assert(&smt::eq(term, &smt::constant(&value.bits)));
    }
    let (Ok(x), Ok(y)) = (
        script.encode(&one, &X86, &initial, "a.", &options),
        script.encode(&two, &X86, &initial, "b.", &options),
    ) else {
        return Separation::Unknown;
    };
    for done in [&x, &y] {
        script.assert(&smt::not(&done.trap));
        script.assert(&smt::not(&done.system_call));
        script.assert(&smt::not(&done.exhausted));
    }
    // The other undefined values the same in both.
    for &(expr, _) in &one.exprs {
        if let Expr::Undefined { serial, .. } = expr {
            let [a, b] = ["a", "b"].map(|side| smt::symbol(&format!("{side}.undefined.{serial}")));
            let declared = |term: &Term| script.as_str().contains(&format!("(declare-fun {term} "));
            if declared(&a) && declared(&b) {
                script.assert(&smt::eq(&a, &b));
            }
        }
    }
    script.assert(&smt::not(&smt::eq(
        x.state.register(output).unwrap(),
        y.state.register(output).unwrap(),
    )));
    script.command("(check-sat)");
    let addresses: Vec<u64> = template.initial.keys().copied().collect();
    for &id in &free {
        let term = initial.register(id).unwrap();
        script.command(&format!("(get-value ({term}))"));
    }
    for &address in &addresses {
        script.command(&format!(
            "(get-value ((select {} {})))",
            initial.memory,
            smt::literal(64, address)
        ));
    }
    let Answers {
        lines: answers,
        exhausted,
    } = z3(script.as_str(), Z3_RLIMIT);
    if exhausted {
        return Separation::Exhausted;
    }
    match answers.first().map(String::as_str) {
        Some("sat") => {}
        Some("unsat") => return Separation::Equal,
        _ => return Separation::Unknown,
    }
    let value = |line: &str| {
        let literal = line.trim_end_matches(')').rsplit(' ').next()?;
        smt::parse_literal(literal)
    };
    let mut values = answers[1..].iter().map(|line| value(line));
    let mut start = case.start.clone();
    for &id in &free {
        let Some(Some(bits)) = values.next() else {
            return Separation::Unknown;
        };
        let name = X86.info(id).unwrap().name;
        if let Some(index) = GPRS.iter().position(|gpr| *gpr == name) {
            start.gprs[index] = bits.low_u64();
        } else if let Some((_, bit)) = FLAGS.iter().find(|(flag, _)| *flag == name) {
            start.rflags = (start.rflags & !(1 << bit)) | (bits.low_u64() << bit);
        } else if let Some(fp) = &mut start.fp {
            if id.0 >= C0.0 && id.0 < C0.0 + 4 {
                let bit = CONDITION_BITS[usize::from(id.0 - C0.0)];
                let fsw = (u64::from(fp.fsw) & !(1 << bit)) | (bits.low_u64() << bit);
                fp.fsw = u16::try_from(fsw).unwrap();
            } else if id.0 >= FPR0.0 && id.0 < FPR0.0 + 8 {
                fp.fpr[usize::from(id.0 - FPR0.0)] = bits.low_u128();
            }
        }
    }
    let mut seeds = BTreeMap::new();
    for &address in &addresses {
        let Some(Some(bits)) = values.next() else {
            return Separation::Unknown;
        };
        seeds.insert(address, u8::try_from(bits.low_u64() & 0xff).unwrap());
    }
    Separation::State(Box::new(Case {
        bytes: case.bytes.clone(),
        instruction: case.instruction.clone(),
        start,
        seeds,
        random: false,
    }))
}

/// The processor's identity, as a profile's `[[measured]]` records it.
struct Measured {
    text: String,
    core_type: u64,
    family: u64,
    model: u64,
}

fn measured(oracle: &mut Oracle, cpus: &str, seed: u64) -> Measured {
    let cpuid = |oracle: &mut Oracle, leaf: u64| {
        let answer = cpu::parse(&oracle.ask(&format!("case {:x} 0fa2 rax={leaf:x}", cpu::CODE)));
        ["rax", "rbx", "rcx", "rdx"].map(|name| answer.values.get(name).copied().unwrap_or(0))
    };
    let [_, b, c, d] = cpuid(oracle, 0);
    let vendor: String = [b, d, c]
        .iter()
        .flat_map(|word| u32::try_from(*word).unwrap().to_le_bytes())
        .map(char::from)
        .collect();
    let [eax1, ..] = cpuid(oracle, 1);
    let [eax1a, ..] = cpuid(oracle, 0x1a);
    let base = (eax1 >> 8) & 0xf;
    let family = base + if base == 0xf { (eax1 >> 20) & 0xff } else { 0 };
    let model = ((eax1 >> 4) & 0xf) | (((eax1 >> 16) & 0xf) << 4);
    let first: u32 = cpus
        .split([',', '-'])
        .next()
        .and_then(|cpu| cpu.parse().ok())
        .unwrap_or(0);
    let microcode = std::fs::read_to_string(format!(
        "/sys/devices/system/cpu/cpu{first}/microcode/version"
    ))
    .unwrap_or_default();
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let name = cpuinfo
        .lines()
        .find_map(|line| line.strip_prefix("model name"))
        .and_then(|rest| rest.split_once(':'))
        .map_or("", |(_, name)| name.trim());
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut text = String::new();
    let _ = writeln!(text, "[[measured]]");
    let _ = writeln!(text, "cpu = {name:?}");
    let _ = writeln!(text, "vendor = {vendor:?}");
    let _ = writeln!(text, "family = {family}");
    let _ = writeln!(text, "model = {model:#x}");
    let _ = writeln!(text, "stepping = {}", eax1 & 0xf);
    let _ = writeln!(text, "cpuid_1_eax = {eax1:#010x}");
    let _ = writeln!(text, "core_type = {:#x}", eax1a >> 24);
    let _ = writeln!(text, "native_model = {:#08x}", eax1a & 0xff_ffff);
    let _ = writeln!(text, "microcode = {}", microcode.trim());
    let _ = writeln!(text, "cpus = {cpus:?}");
    let _ = writeln!(text, "kernel = \"Linux {}\"", kernel.trim());
    let _ = writeln!(text, "date = {}", today());
    let _ = writeln!(text, "seed = {seed:#018x}");
    Measured {
        text,
        core_type: eax1a >> 24,
        family,
        model,
    }
}

/// Today's date (UTC), `2026-11-14`.
fn today() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Days to a civil date (Howard Hinnant's algorithm).
    let days = i64::try_from(seconds / 86_400).unwrap() + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year}-{month:02}-{day:02}")
}

/// The sites to measure, as `BINBUN_PROFILE_SITES` says.
fn chosen_sites() -> BTreeSet<SiteId> {
    let all = (0..u16::try_from(SITES.len()).unwrap()).map(SiteId);
    match std::env::var("BINBUN_PROFILE_SITES").as_deref() {
        Err(_) | Ok("all") => all.collect(),
        Ok("corpus") => {
            let corpus = std::env::var("BINBUN_PROFILE_CORPUS").unwrap_or_else(|_| {
                [
                    "/usr/bin/bash",
                    "/usr/lib/libc.so.6",
                    "/usr/lib/libstdc++.so.6",
                    "/usr/bin/rg",
                ]
                .join(":")
            });
            let mut forms = BTreeSet::new();
            for path in corpus.split(':').filter(|p| !p.is_empty()) {
                forms.extend(
                    support::sweep(path)
                        .iter()
                        .map(|found| found.instruction.form()),
                );
            }
            all.filter(|site| {
                SITES[usize::from(site.0)]
                    .forms
                    .iter()
                    .any(|form| forms.contains(form))
            })
            .collect()
        }
        Ok(names) => names
            .split(',')
            .map(|name| {
                X86.find_site(name.trim())
                    .unwrap_or_else(|| panic!("no site {name}"))
            })
            .collect(),
    }
}

/// Runs `cases` on `workers` threads, each with its own oracle; their
/// results in order. The cases' randomness is per case, so the results do
/// not depend on the threads.
fn run_all(oracle_path: &str, cases: &[Case], workers: usize, seed: u64) -> Vec<Ran> {
    let next = Mutex::new(0usize);
    let results: Mutex<Vec<Option<Ran>>> = Mutex::new((0..cases.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                let mut oracle = Oracle::start(oracle_path);
                loop {
                    let index = {
                        let mut next = next.lock().unwrap();
                        let index = *next;
                        *next += 1;
                        index
                    };
                    let Some(case) = cases.get(index) else {
                        break;
                    };
                    let mut random =
                        Random((seed ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)) | 1);
                    let ran = run_case(&mut oracle, case, &mut random);
                    results.lock().unwrap()[index] = Some(ran);
                }
            });
        }
    });
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .map(Option::unwrap_or_default)
        .collect()
}

/// A site's result: its rule (or `unknown`, `varies`) and the record.
struct Found {
    rule: String,
    observations: usize,
    random: usize,
    systematic: usize,
    separating: usize,
    beaten: Vec<String>,
    equivalent: Vec<String>,
    credible: bool,
    note: Option<String>,
}

/// The rule search for one site: the candidates every observation allows,
/// then states z3 finds to separate the survivors, run through `oracle`,
/// until one is left, the rest are proved equal or the separations run
/// out.
#[expect(clippy::too_many_lines, reason = "the search's steps in order")]
fn search(
    site: SiteId,
    seen: &mut Seen,
    cases: &mut Vec<Case>,
    oracle: &mut Oracle,
    report: &mut String,
) -> Found {
    let info = X86.site(site).unwrap();
    let mut found = Found {
        rule: "unknown".to_owned(),
        observations: 0,
        random: 0,
        systematic: 0,
        separating: 0,
        beaten: Vec::new(),
        equivalent: Vec::new(),
        credible: false,
        note: None,
    };
    let Some(first) = seen.observations.first() else {
        found.note = Some("no state reached it on this processor".to_owned());
        return found;
    };
    let widths: Vec<u16> = first.inputs.iter().map(Value::width).collect();
    let mut candidates: Vec<Candidate> = library(info.inputs, &widths, first.cpu.width())
        .into_iter()
        .filter_map(|text| Candidate::new(text, info.inputs))
        .collect();
    let mut checked = 0;
    let mut separations = 0;
    let mut random = Random(0x5151_5151 ^ u64::from(site.0) | 1);
    loop {
        for observation in &seen.observations[checked..] {
            for candidate in candidates.iter_mut().filter(|c| c.verdict.refuted == 0) {
                candidate.check(observation);
            }
        }
        checked = seen.observations.len();
        let mut alive: Vec<usize> = (0..candidates.len())
            .filter(|&i| candidates[i].alive())
            .collect();
        alive.sort_by_key(|&i| (candidates[i].text.len(), i));
        if alive.len() < 2 || separations >= 40 {
            break;
        }
        // Separate the two simplest survivors.
        let (a, b) = (alive[0], alive[1]);
        let templates: Vec<usize> = templates(seen);
        let mut outcome = Separation::Unknown;
        for &template in &templates {
            outcome = separate(
                &cases[template],
                site,
                &candidates[a].rule,
                &candidates[b].rule,
            );
            if !matches!(outcome, Separation::Equal) {
                break;
            }
        }
        separations += 1;
        match outcome {
            Separation::State(case) => {
                found.separating += 1;
                let ran = run_case(oracle, &case, &mut random);
                let before = seen.observations.len();
                add(seen, site, &ran, cases, &case);
                if seen.observations.len() == before {
                    // The state did not reach the site on the processor:
                    // the simpler one stays, unproved.
                    found.note = Some(format!(
                        "`{}` and `{}` not separated (z3's state did not reach the site)",
                        candidates[a].text, candidates[b].text
                    ));
                    candidates[b].verdict.refuted = usize::MAX;
                }
            }
            Separation::Equal => {
                found.equivalent.push(candidates[b].text.clone());
                candidates[b].verdict.refuted = usize::MAX;
            }
            Separation::Exhausted => {
                // As below, but the measurement's limit was too small.
                found.note = Some(format!(
                    "`{}` and `{}` not separated (z3 reached its resource limit)",
                    candidates[a].text, candidates[b].text
                ));
                candidates[b].verdict.refuted = usize::MAX;
            }
            Separation::Unknown => {
                // z3 cannot tell; the simpler one stays, unproved.
                found.note = Some(format!(
                    "`{}` and `{}` not separated (z3 gave no answer)",
                    candidates[a].text, candidates[b].text
                ));
                candidates[b].verdict.refuted = usize::MAX;
            }
        }
    }
    let mut alive: Vec<usize> = (0..candidates.len())
        .filter(|&i| candidates[i].alive())
        .collect();
    alive.sort_by_key(|&i| (candidates[i].text.len(), i));
    // The closest rivals: refuted by the fewest observations, each then
    // refuted again by a state chosen for it.
    let mut rivals: Vec<usize> = (0..candidates.len())
        .filter(|&i| {
            let verdict = &candidates[i].verdict;
            verdict.refuted > 0 && verdict.refuted != usize::MAX
        })
        .collect();
    rivals.sort_by_key(|&i| (candidates[i].verdict.refuted, candidates[i].text.len(), i));
    rivals.truncate(4);
    if let Some(&winner) = alive.first() {
        for &rival in &rivals {
            for template in templates(seen) {
                if let Separation::State(case) = separate(
                    &cases[template],
                    site,
                    &candidates[winner].rule,
                    &candidates[rival].rule,
                ) {
                    found.separating += 1;
                    let ran = run_case(oracle, &case, &mut random);
                    add(seen, site, &ran, cases, &case);
                    break;
                }
            }
        }
        for observation in &seen.observations[checked..] {
            candidates[winner].check(observation);
        }
    }
    found.beaten = rivals.iter().map(|&i| candidates[i].text.clone()).collect();
    found.observations = seen.observations.len();
    found.random = seen.observations.iter().filter(|o| o.random).count();
    found.systematic = seen
        .observations
        .iter()
        .filter(|o| !o.random && o.case.is_some())
        .count();
    if seen.varies {
        "varies".clone_into(&mut found.rule);
        found.note = Some("one state gave two answers".to_owned());
        return found;
    }
    match alive.first() {
        Some(&winner) if candidates[winner].alive() => {
            found.rule.clone_from(&candidates[winner].text);
            found.credible = found.random >= RANDOM_NEEDED && found.note.is_none();
            if found.random < RANDOM_NEEDED {
                found.note = Some(format!("only {} random observations", found.random));
            }
        }
        _ => {
            found.note = Some("no candidate fits".to_owned());
            let _ = writeln!(report, "{}: no candidate fits; observations:", info.name);
            for observation in seen.observations.iter().take(20) {
                let inputs: Vec<String> = observation
                    .inputs
                    .iter()
                    .map(|v| format!("{}", v.bits))
                    .collect();
                let _ = writeln!(report, "  ({}) -> {}", inputs.join(", "), observation.cpu);
            }
            closest(info.inputs, &mut candidates, &seen.observations, report);
        }
    }
    found
}

/// The candidates refuted by the fewest of `observations` (each counted
/// again over them all), each with the first observations refuting it and
/// what it gives there: where a library lacks a rule, what is closest.
fn closest(
    names: &[&str],
    candidates: &mut [Candidate],
    observations: &[Observation],
    report: &mut String,
) {
    let mut counted: Vec<(usize, usize)> = candidates
        .iter_mut()
        .enumerate()
        .map(|(i, candidate)| {
            let refuted = observations
                .iter()
                .filter(|o| candidate.refuted_by(o) == Some(true))
                .count();
            (refuted, i)
        })
        .collect();
    counted.sort_by_key(|&(refuted, i)| (refuted, candidates[i].text.len(), i));
    let _ = writeln!(report, "  inputs ({})", names.join(", "));
    for &(refuted, i) in counted.iter().take(3) {
        let candidate = &mut candidates[i];
        let _ = writeln!(
            report,
            "  closest `{}`: refuted by {refuted} of {}",
            candidate.text,
            observations.len()
        );
        let mut shown = 0;
        for observation in observations {
            if shown == 8 {
                break;
            }
            if candidate.refuted_by(observation) != Some(true) {
                continue;
            }
            shown += 1;
            let inputs: Vec<String> = observation
                .inputs
                .iter()
                .map(|v| format!("{}", v.bits))
                .collect();
            let gives = match candidate.predict(observation) {
                Ok(Some(bits)) => format!("{bits}"),
                Ok(None) => "unknown".to_owned(),
                Err(()) => "nothing".to_owned(),
            };
            let _ = writeln!(
                report,
                "    ({}) -> {}, it gives {gives}",
                inputs.join(", "),
                observation.cpu
            );
        }
    }
}

/// Cases to ask z3 about: the first observed case of each input widths.
fn templates(seen: &Seen) -> Vec<usize> {
    let mut by_widths: BTreeMap<Vec<u16>, usize> = BTreeMap::new();
    for observation in &seen.observations {
        if let Some(case) = observation.case {
            let widths = observation.inputs.iter().map(Value::width).collect();
            by_widths.entry(widths).or_insert(case);
        }
    }
    by_widths.into_values().collect()
}

/// Adds `ran`'s observation of `site` (from `case`) to `seen`.
fn add(seen: &mut Seen, site: SiteId, ran: &Ran, cases: &mut Vec<Case>, case: &Case) {
    for (other, inputs, cpu) in &ran.observations {
        if *other != site {
            continue;
        }
        cases.push(case.clone());
        seen.observations.push(Observation {
            inputs: inputs.clone(),
            cpu: *cpu,
            random: false,
            case: Some(cases.len() - 1),
        });
    }
}

/// The profile's id and title for this core type.
fn identity(measured: &Measured) -> (String, String) {
    if let Ok(id) = std::env::var("BINBUN_PROFILE_ID") {
        return (id.clone(), id);
    }
    let raptor_lake = measured.family == 6 && [0xb7, 0xba, 0xbf].contains(&measured.model);
    match (raptor_lake, measured.core_type) {
        (true, 0x40) => (
            "intel-raptor-cove".to_owned(),
            "Intel Raptor Cove (P-cores of 13th- and 14th-generation Core)".to_owned(),
        ),
        (true, 0x20) => (
            "intel-gracemont".to_owned(),
            "Intel Gracemont (E-cores of 13th- and 14th-generation Core)".to_owned(),
        ),
        _ => panic!("unknown microarchitecture: set BINBUN_PROFILE_ID"),
    }
}

/// The TOML string of `text`.
fn quoted(text: &str) -> String {
    format!("{text:?}")
}

#[test]
#[ignore = "needs the CPU oracle: BINBUN_CPU_ORACLE=target/cpu-oracle"]
#[expect(clippy::similar_names, reason = "seed and seen")]
#[expect(clippy::too_many_lines, reason = "the measurement's steps in order")]
fn measure_this_core_type() {
    let oracle_path = std::env::var("BINBUN_CPU_ORACLE").expect("BINBUN_CPU_ORACLE");
    let cpus = allowed_cpus();
    let core = cpu::core_type(&cpus);
    assert!(
        core.is_some(),
        "run on one core type: taskset -c 0-15 (P) or 16-31 (E) (allowed now: {cpus})"
    );
    let seed = std::env::var("BINBUN_PROFILE_SEED").map_or(0x5eed_1234_abcd_ef01, |v| {
        u64::from_str_radix(v.trim_start_matches("0x"), 16).unwrap()
    });
    let per_form = std::env::var("BINBUN_PROFILE_PER_FORM").map_or(4, |v| v.parse().unwrap());
    let states: u64 = std::env::var("BINBUN_PROFILE_STATES").map_or(48, |v| v.parse().unwrap());
    let workers = cpu::cpu_list(&cpus).len().max(1);
    let mut oracle = Oracle::start(&oracle_path);
    let measured = measured(&mut oracle, &cpus, seed);
    let (id, title) = identity(&measured);

    let sites = chosen_sites();
    let forms: BTreeSet<Form> = sites
        .iter()
        .flat_map(|site| SITES[usize::from(site.0)].forms.iter().copied())
        .collect();
    let corpus: Vec<String> = std::env::var("BINBUN_LIFT_CORPUS")
        .unwrap_or_default()
        .split(':')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect();
    // Up to `per_form` encodings of each form per operand width: a site
    // of one width only (16-bit SHLD's destination) needs encodings of it.
    let mut kept: BTreeMap<(Form, u32), usize> = BTreeMap::new();
    let encodings: Vec<(Form, Vec<u8>, Instruction)> = cpu::instructions(
        per_form * 128,
        &corpus,
        &|form| forms.contains(&form),
        1_200_000,
    )
    .into_iter()
    .filter(|(form, _, instruction)| {
        let count = kept
            .entry((*form, instruction.operand_width()))
            .or_default();
        *count += 1;
        *count <= per_form
    })
    .collect();
    println!(
        "{id}: {} sites, {} forms, {} encodings, {workers} workers",
        sites.len(),
        forms.len(),
        encodings.len()
    );

    // Systematic and random cases of every encoding.
    let mut random = Random(seed);
    let mut cases: Vec<Case> = Vec::new();
    for (_, bytes, instruction) in &encodings {
        for i in 0..SYSTEMATIC {
            let (start, seeds) = systematic(instruction, i, &mut random);
            cases.push(Case {
                bytes: bytes.clone(),
                instruction: instruction.clone(),
                start,
                seeds,
                random: false,
            });
        }
        for _ in 0..states {
            let (start, seeds) = random_case(instruction, &mut random);
            cases.push(Case {
                bytes: bytes.clone(),
                instruction: instruction.clone(),
                start,
                seeds,
                random: true,
            });
        }
    }
    let mut seen: BTreeMap<SiteId, Seen> =
        sites.iter().map(|&site| (site, Seen::default())).collect();
    let mut disagreements: Vec<String> = Vec::new();
    let mut gather =
        |cases: &[Case], from: usize, ran: Vec<Ran>, seen: &mut BTreeMap<SiteId, Seen>| {
            for (offset, ran) in ran.into_iter().enumerate() {
                let index = from + offset;
                if let Some(text) = ran.disagrees {
                    disagreements.push(text);
                    continue;
                }
                for (site, inputs, cpu) in ran.observations {
                    if let Some(entry) = seen.get_mut(&site) {
                        entry.observations.push(Observation {
                            inputs,
                            cpu,
                            random: cases[index].random,
                            case: Some(index),
                        });
                    }
                }
            }
        };
    let ran = run_all(&oracle_path, &cases, workers, seed);
    gather(&cases, 0, ran, &mut seen);

    // The same states again, now and then: a different answer varies.
    let again: Vec<usize> = (0..cases.len()).step_by(8).collect();
    let repeated: Vec<Case> = again.iter().map(|&i| cases[i].clone()).collect();
    let rerun = run_all(&oracle_path, &repeated, workers, seed);
    let first = run_all(&oracle_path, &repeated, workers, seed);
    for (one, two) in first.iter().zip(&rerun) {
        for (site, inputs, cpu) in &one.observations {
            let differs = two
                .observations
                .iter()
                .any(|(other, again, cpu2)| other == site && again == inputs && cpu2 != cpu);
            if differs && let Some(entry) = seen.get_mut(site) {
                entry.varies = true;
            }
        }
    }

    // More random states for sites short of observations (a form of one
    // encoding, `fldz`, or that faults on most states, `div`).
    for round in 0..6u64 {
        let short: Vec<SiteId> = seen
            .iter()
            .filter(|(_, s)| s.observations.iter().filter(|o| o.random).count() < RANDOM_NEEDED)
            .map(|(&site, _)| site)
            .collect();
        if short.is_empty() {
            break;
        }
        let short_forms: BTreeSet<Form> = short
            .iter()
            .flat_map(|site| SITES[usize::from(site.0)].forms.iter().copied())
            .collect();
        let from = cases.len();
        let mut random = Random(seed ^ (round + 1).wrapping_mul(0x51ed) | 1);
        for (form, bytes, instruction) in &encodings {
            if !short_forms.contains(form) {
                continue;
            }
            for _ in 0..states * 8 {
                let (start, seeds) = random_case(instruction, &mut random);
                cases.push(Case {
                    bytes: bytes.clone(),
                    instruction: instruction.clone(),
                    start,
                    seeds,
                    random: true,
                });
            }
        }
        let ran = run_all(&oracle_path, &cases[from..], workers, seed ^ round);
        gather(&cases, from, ran, &mut seen);
    }

    // The rule search, site by site.
    let mut report = String::new();
    let mut text = String::new();
    let _ = writeln!(
        text,
        "# What {title} does where L0 leaves a value undefined:"
    );
    let _ = writeln!(
        text,
        "# measured by crates/binbun-x86-lift/tests/profile.rs."
    );
    let _ = writeln!(text, "format = 1");
    let _ = writeln!(text, "id = {}", quoted(&id));
    let _ = writeln!(text, "title = {}", quoted(&title));
    let _ = writeln!(text, "architecture = \"x86-64\"");
    let revision: u32 = std::env::var("BINBUN_PROFILE_REVISION").map_or(1, |v| v.parse().unwrap());
    let _ = writeln!(text, "revision = {revision}");
    let _ = writeln!(text, "sites = {}", quoted(&site_table_hash()));
    let _ = writeln!(text);
    text.push_str(&measured.text);
    let (mut rules, mut unknown, mut varies, mut incredible) = (0, 0, 0, 0);
    for (&site, entry) in &mut seen {
        let found = search(site, entry, &mut cases, &mut oracle, &mut report);
        let name = X86.site(site).unwrap().name;
        let _ = writeln!(text);
        let _ = writeln!(text, "[site.{}]", quoted(name));
        let _ = writeln!(text, "rule = {}", quoted(&found.rule));
        let _ = writeln!(text, "observations = {}", found.observations);
        let _ = writeln!(text, "random = {}", found.random);
        let _ = writeln!(text, "systematic = {}", found.systematic);
        let _ = writeln!(text, "separating = {}", found.separating);
        let list = |items: &[String]| {
            items
                .iter()
                .map(|item| quoted(item))
                .collect::<Vec<_>>()
                .join(", ")
        };
        if !found.beaten.is_empty() {
            let _ = writeln!(text, "beaten = [{}]", list(&found.beaten));
        }
        if !found.equivalent.is_empty() {
            let _ = writeln!(text, "equivalent = [{}]", list(&found.equivalent));
        }
        match found.rule.as_str() {
            "unknown" => unknown += 1,
            "varies" => varies += 1,
            _ => {
                rules += 1;
                if !found.credible {
                    incredible += 1;
                    let _ = writeln!(text, "credible = false");
                }
            }
        }
        if let Some(note) = &found.note {
            let _ = writeln!(text, "note = {}", quoted(note));
        }
        println!(
            "{name}: {} ({} observations, {} random)",
            found.rule, found.observations, found.random
        );
    }
    if core == Some(cpu::Core::Performance) {
        let _ = writeln!(text);
        let _ = writeln!(text, "[notes]");
        let _ = writeln!(
            text,
            "non_canonical = \"keeps effects of an instruction faulting on a non-canonical address (call's return address, vcvtps2ph's MXCSR flags); defined behaviour, not applied\""
        );
    }
    println!(
        "{id}: {rules} rules ({incredible} not credible), {unknown} unknown, {varies} varies; {} cases, {} L0 disagreements",
        cases.len(),
        disagreements.len()
    );
    println!(
        "z3: the hardest query took {} of its resource limit {Z3_RLIMIT}",
        Z3_HARDEST.load(Ordering::Relaxed)
    );
    if let Ok(path) = std::env::var("BINBUN_PROFILE_OUT") {
        std::fs::write(&path, &text).unwrap();
        // It reads back as a profile.
        profiles::parse(&text).unwrap();
    }
    if let Ok(path) = std::env::var("BINBUN_PROFILE_REPORT") {
        report.push_str("\nL0 disagreements:\n");
        report.push_str(&disagreements.join("\n"));
        std::fs::write(&path, &report).unwrap();
    }
}

/// The rules a first probe measured per site (an i9-14900F, 2026-11-13),
/// for P-cores and E-cores; `None` where the core type's rule is the
/// other's.
const PROBE: [(&str, &str, &str); 9] = [
    (
        "shrd.of",
        "bit(src, 0) ^ msb(dst)",
        "msb(defined.dst) ^ bit(defined.dst, osz - 2)",
    ),
    ("shr.of", "msb(dst)", "0"),
    ("sar.of", "0", "0"),
    (
        "shl.of",
        "msb(dst) ^ bit(dst, osz - 2)",
        "msb(defined.dst) ^ defined.cf",
    ),
    ("shrd.af", "0", "0"),
    ("shl.af", "0", "0"),
    ("bt.of", "old", "old"),
    ("fnstcw.c0", "old", "old"),
    ("tzcnt.af", "0", "0"),
];

/// Runs `encodings` from random states and compares `profile`'s value at
/// `site` with `rule`'s wherever the rule's is defined; how many it
/// compared.
fn agrees(
    profile: &Profile,
    site: SiteId,
    rule: &str,
    encodings: &[(Form, Vec<u8>, Instruction)],
) -> Result<usize, String> {
    let info = X86.site(site).unwrap();
    let expected = Rule::parse(rule, info.inputs).map_err(|e| e.0)?;
    let mut random = Random(0x0bad_cafe | 1);
    let mut compared = 0;
    for (form, bytes, instruction) in encodings {
        if !SITES[usize::from(site.0)].forms.contains(form) {
            continue;
        }
        for _ in 0..200 {
            let (start, seeds) = random_case(instruction, &mut random);
            let semantics = lift(instruction, Mode::Bits64, start.code).unwrap();
            let mut machine = start.machine(bytes, &seeds, &mut random);
            if interpret::run(&semantics, &mut machine) == Outcome::Undetermined {
                continue;
            }
            for (other, inputs) in std::mem::take(&mut machine.sites) {
                if other != site {
                    continue;
                }
                let widths: Vec<u16> = inputs.iter().map(Value::width).collect();
                let width = width_of(&semantics, site).unwrap();
                let want = expected
                    .instantiate(&widths, width)
                    .map_err(|e| e.0)?
                    .eval(&inputs)
                    .map_err(|e| e.0)?;
                let got = profile.value(site, &inputs, width);
                if want.is_defined() && got != want {
                    return Err(format!(
                        "`{}`: {} for {inputs:?}, the probe's rule {}",
                        instruction.intel(start.code),
                        got.bits,
                        want.bits
                    ));
                }
                compared += 1;
            }
        }
    }
    Ok(compared)
}

/// z3 under a resource limit answers the same every time, and a query
/// needing more than the limit is `exhausted`, not an answer.
#[test]
fn z3_stops_at_its_resource_limit_every_time() {
    if Command::new("z3").arg("--version").output().is_err() {
        eprintln!("skipped: cannot run z3");
        return;
    }
    // Factoring a 64-bit product: far beyond 2,000 of z3's steps.
    let hard = "(declare-const x (_ BitVec 64))\n(declare-const y (_ BitVec 64))\n\
        (assert (= (bvmul x y) #x9e3779b97f4a7c15))\n\
        (assert (bvugt x #x0000000000000001))\n(assert (bvugt y #x0000000000000001))\n\
        (assert (bvult x #x00000000ffffffff))\n(assert (bvult y #x00000000ffffffff))\n\
        (check-sat)\n(get-value (x))\n";
    let first = z3(hard, 2000);
    let again = z3(hard, 2000);
    assert!(first.exhausted && again.exhausted);
    assert_eq!(first.lines, again.lines);
    assert_eq!(first.lines.first().map(String::as_str), Some("unknown"));
    let easy = "(declare-const x (_ BitVec 8))\n\
        (assert (= (bvadd x #x01) #x00))\n(check-sat)\n(get-value (x))\n";
    let answers = z3(easy, Z3_RLIMIT);
    assert!(!answers.exhausted);
    assert_eq!(answers.lines, ["sat", "((x #xff))"]);
}

/// Both profiles have the probe's rules where they cover its sites, and
/// the SHRD example gives what the processors gave.
#[test]
fn the_profiles_have_the_probes_rules() {
    let p = profiles::resolve("intel-raptor-cove").unwrap();
    let e = profiles::resolve("intel-gracemont").unwrap();
    // Every site has a rule, `unknown` or `varies`.
    for profile in [&p, &e] {
        let missing: Vec<&str> = (0..SITES.len())
            .filter(|&i| profile.choices[i].is_none())
            .map(|i| X86.sites[i].name)
            .collect();
        assert!(
            missing.is_empty(),
            "{}: no entry for {missing:?}",
            profile.id
        );
    }
    let shrd = X86.find_site("shrd.of").unwrap();
    let flags = |dst: u64, result: u64, osz: u16| {
        [
            Value::defined(Bits::from_u64(osz, dst)),
            Value::defined(Bits::from_u64(osz, dst)),
            Value::defined(Bits::from_u64(8, 0x1d)),
            Value::defined(Bits::from_u64(1, 0)),
            Value::defined(Bits::from_u64(osz, result)),
            Value::defined(Bits::from_u64(1, 0)),
        ]
    };
    let of = |profile: &Profile, inputs: &[Value]| {
        profile.value(shrd, inputs, 1).known().unwrap().low_u64()
    };
    // rdx = 0x4780000000: 0 on both.
    let probe = flags(0x47_8000_0000, 0x23c, 64);
    assert_eq!((of(&p, &probe), of(&e, &probe)), (0, 0));
    // The post's rdx = 0x8f: 1 on the P-cores, 0 on the E-cores.
    let post = flags(0x8f, 0x478_0000_0000, 64);
    assert_eq!((of(&p, &post), of(&e, &post)), (1, 0));
    // edx = 0x80000000: 1 on the P-cores, 0 on the E-cores.
    let narrow = flags(0x8000_0000, 4, 32);
    assert_eq!((of(&p, &narrow), of(&e, &narrow)), (1, 0));
    // The probe's rules, compared where the profiles' rules apply.
    let forms: BTreeSet<Form> = PROBE
        .iter()
        .flat_map(|(name, ..)| {
            SITES[usize::from(X86.find_site(name).unwrap().0)]
                .forms
                .iter()
                .copied()
        })
        .collect();
    let encodings = cpu::instructions(2, &[], &|form| forms.contains(&form), 0);
    for (name, p_rule, e_rule) in PROBE {
        let site = X86.find_site(name).unwrap();
        for (profile, rule) in [(&p, p_rule), (&e, e_rule)] {
            if profile.rule(site).is_none() {
                continue;
            }
            let compared = agrees(profile, site, rule, &encodings)
                .unwrap_or_else(|e| panic!("{}: {name}: {e}", profile.id));
            assert!(compared > 0, "{}: {name}: never reached", profile.id);
        }
    }
}
