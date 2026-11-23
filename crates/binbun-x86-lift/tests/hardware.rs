//! L0 against the CPU this runs on: each instruction with semantics, from
//! real code, runs once in the L0 interpreter and once on the processor
//! (`tools/cpu-oracle`) from the same state, and the results must agree on
//! every bit L0 defines.
//!
//! ```sh
//! sh scripts/cpu-oracle.sh
//! BINBUN_CPU_ORACLE=$PWD/target/cpu-oracle \
//!   cargo test --release -p binbun-x86-lift --test hardware -- --ignored --nocapture
//! ```
//!
//! - `BINBUN_LIFT_CORPUS`: colon-separated files to take instructions from
//!   (default: the fixtures and `/usr/lib/libc.so.6`).
//! - `BINBUN_LIFT_PER_FORM`: distinct encodings per form (default 40).
//! - `BINBUN_LIFT_STATES`: states per instruction (default 8).
//! - `BINBUN_LIFT_SEED`: the random seed.
//! - `BINBUN_LIFT_REPORT`: a file to write every mismatch to.
//! - `BINBUN_LIFT_FORMS`: comma-separated beginnings of form names (as
//!   `ADDPS`, `VFMADD`); only forms whose name starts with one are run.
//! - `BINBUN_LIFT_ANY_CORE`: set to run on any core of a hybrid processor
//!   (to compare the core types; see below).
//! - `BINBUN_LIFT_PROFILE`: a processor profile, a shipped one's name
//!   (`intel-raptor-cove`) or a file's path: the values L0 leaves
//!   undefined at its sites are the profile's rules', and compared too.
//!
//! APX encodings (the REX2 prefix) are skipped: this processor has no APX
//! and raises `#UD` for them (Intel SDE can check them later).
//!
//! On a hybrid processor the test runs only on the efficiency cores
//! (`taskset -c 16-31` on the i9-14900F; it refuses other CPUs unless
//! `BINBUN_LIFT_ANY_CORE` is set): where the core types differ, L0
//! follows the E-cores. The P-cores keep effects
//! of an instruction that faults on a non-canonical address (`call`'s
//! pushed return address, `vcvtps2ph`'s MXCSR flags, or `#XM` first),
//! skip the address check of an x87 store an unmasked exception suppresses,
//! and choose another NaN in `dpps` sums. With a profile it runs on the
//! CPUs the profile was measured on; on the P-cores the first (defined
//! behaviour, which profiles never change) is excused, and so are the
//! other two, which L0 does not make sites yet: each is counted.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

mod support;

#[allow(dead_code, reason = "shared with the profile measurement")]
#[path = "support/cpu.rs"]
mod cpu;

use std::collections::BTreeMap;
use std::sync::Arc;

use binbun_semantics::interpret::{self, Outcome};
use binbun_semantics::ir::Trap;
use binbun_x86::{Form, Mode};
use binbun_x86_lift::lift;
use binbun_x86_lift::profiles;

use cpu::{Core, FpState, Oracle, Random, Start};

/// Why a mismatch on the P-cores is excused: the fault leftovers (defined
/// behaviour), or a choice L0 made for the E-cores.
fn excuse(form: Form, outcome: Outcome, kind: &str) -> Option<&'static str> {
    let name = format!("{form:?}");
    if outcome == Outcome::Trap(Trap::Protection) && kind == "fault" {
        return Some("a fault's leftovers (non-canonical address)");
    }
    if name.starts_with("DPPS") || name.starts_with("VDPPS") {
        return Some("dpps's NaN choice");
    }
    if matches!(outcome, Outcome::Trap(Trap::Protection | Trap::Stack))
        && ["FST", "FIST", "FBSTP"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
    {
        return Some("an x87 store an unmasked exception suppresses");
    }
    None
}

#[test]
#[ignore = "needs the CPU oracle: BINBUN_CPU_ORACLE=target/cpu-oracle"]
#[expect(clippy::similar_names, reason = "code and core")]
#[expect(
    clippy::too_many_lines,
    reason = "one loop over the cases, read in order"
)]
fn semantics_match_the_processor() {
    let oracle_path = std::env::var("BINBUN_CPU_ORACLE").expect("BINBUN_CPU_ORACLE");
    let profile = std::env::var("BINBUN_LIFT_PROFILE")
        .ok()
        .map(|name| Arc::new(profiles::resolve(&name).unwrap()));
    let allowed = cpu::allowed_cpus();
    let core = cpu::core_type(&allowed);
    let any_core = std::env::var_os("BINBUN_LIFT_ANY_CORE").is_some();
    let hybrid = std::path::Path::new("/sys/devices/cpu_atom/cpus").exists();
    match &profile {
        Some(profile) => assert!(
            cpu::cpu_list(&allowed).is_subset(&cpu::cpu_list(&profile.measured.cpus)),
            "{} was measured on CPUs {}: run there (allowed now: {allowed})",
            profile.id,
            profile.measured.cpus
        ),
        None => assert!(
            any_core || !hybrid || core == Some(Core::Efficiency),
            "L0 follows the efficiency cores where the core types differ, so run on \
             them only (taskset -c 16-31 on the i9-14900F; allowed now: {allowed}), \
             or set BINBUN_LIFT_ANY_CORE=1 to compare with any core"
        ),
    }
    let excusing = profile.is_some() && core == Some(Core::Performance);
    let per_form = std::env::var("BINBUN_LIFT_PER_FORM").map_or(40, |v| v.parse().unwrap());
    let states = std::env::var("BINBUN_LIFT_STATES").map_or(8, |v| v.parse().unwrap());
    let seed =
        std::env::var("BINBUN_LIFT_SEED").map_or(0x5eed_1234_abcd_ef01, |v| v.parse().unwrap());
    let corpus: Vec<String> = if let Ok(list) = std::env::var("BINBUN_LIFT_CORPUS") {
        list.split(':')
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect()
    } else {
        {
            let mut files: Vec<String> = [
                "program-x86_64.elf",
                "exceptions-x86_64.elf",
                "program-x86_64.exe",
            ]
            .iter()
            .map(|name| support::fixture(name))
            .collect();
            if std::path::Path::new("/usr/lib/libc.so.6").exists() {
                files.push("/usr/lib/libc.so.6".to_owned());
            }
            files
        }
    };
    let only = std::env::var("BINBUN_LIFT_FORMS").unwrap_or_default();
    let wanted = |form: Form| {
        let name = format!("{form:?}");
        only.is_empty()
            || only
                .split(',')
                .any(|prefix| name.starts_with(prefix.trim()))
    };
    let mut random = Random(seed);
    let mut oracle = Oracle::start(&oracle_path);

    let mut checked: BTreeMap<Form, u32> = BTreeMap::new();
    let (mut skipped, mut undetermined) = (0u32, 0u32);
    let mut mismatches: Vec<String> = Vec::new();
    let mut excused: BTreeMap<&str, u32> = BTreeMap::new();
    for (form, bytes, instruction) in cpu::instructions(per_form, &corpus, &wanted, 1_200_000) {
        for _ in 0..states {
            let code = cpu::CODE + random.below(1 << 20) * cpu::PAGE + random.below(cpu::PAGE - 16);
            let semantics = lift(&instruction, Mode::Bits64, code).unwrap();
            let (gprs, seeds) = cpu::state(&instruction, &mut random);
            let rflags = (random.next() & 0xcd5) | 0x2;
            let fp = cpu::uses_fp(&instruction).then(|| FpState::random(&mut random));
            let start = Start {
                code,
                gprs,
                rflags,
                fp,
            };
            let mut machine = start.machine(&bytes, &seeds, &mut random);
            machine.profile.clone_from(&profile);
            let outcome = interpret::run(&semantics, &mut machine);

            // Never run a system call on the processor: with random
            // registers it could do anything the user can.
            if matches!(outcome, Outcome::Undetermined | Outcome::SystemCall) {
                undetermined += 1;
                continue;
            }

            let line = start.line(&bytes, &machine.initial);
            let answer = cpu::parse(&oracle.ask(&line));
            let text = instruction.intel(code).to_string();
            let mut wrong = Vec::new();
            if answer.kind == "skip" {
                skipped += 1;
                continue;
            }
            // A gather faulting on its first element has normalized its
            // mask first; L0's exceptions are precise, so that takes two
            // executions (the first repeats the instruction). If L0 repeats
            // the instruction where the processor faulted, run it once more.
            let outcome = if outcome == Outcome::Transfer(code)
                && answer.kind == "fault"
                && answer.values.get("rip") == Some(&code)
            {
                interpret::run(&semantics, &mut machine)
            } else {
                outcome
            };
            if let Some(rip) = cpu::resumes_at(outcome, &answer, code, code + bytes.len() as u64) {
                // The state after the instruction, or (exceptions being
                // precise) the state before it after a fault.
                cpu::compare(&mut machine, &answer, rip, &mut wrong);
                if start.fp.is_some() {
                    let fault = outcome == Outcome::Trap(Trap::FloatingPoint);
                    cpu::compare_fp(&mut machine, &answer, fault, &mut wrong);
                }
            } else {
                wrong.push(format!("L0 {outcome:?}, CPU {}", answer.kind));
            }
            *checked.entry(form).or_default() += 1;
            if wrong.is_empty() {
                continue;
            }
            if excusing && let Some(why) = excuse(form, outcome, &answer.kind) {
                *excused.entry(why).or_default() += 1;
                continue;
            }
            mismatches.push(format!(
                "{form:?} `{text}`\n  {line}\n  {}",
                wrong.join("\n  ")
            ));
        }
    }
    let cases: u32 = checked.values().sum();
    println!(
        "{cases} cases over {} forms; {skipped} skipped by the oracle, {undetermined} undetermined; {} mismatches; excused {excused:?}; profile {}",
        checked.len(),
        mismatches.len(),
        profile
            .as_ref()
            .map_or("none", |profile| profile.id.as_str())
    );
    if let Ok(path) = std::env::var("BINBUN_LIFT_REPORT") {
        std::fs::write(&path, mismatches.join("\n")).unwrap();
    }
    assert!(
        mismatches.is_empty(),
        "{}",
        mismatches
            .iter()
            .take(25)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(cases > 1000, "too few cases: {cases}");
}
