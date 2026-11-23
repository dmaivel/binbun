//! x86 L0 through the SMT encoding (`binbun_semantics::smt`), proved with
//! z3: facts about single instructions, equivalences and differences of
//! instruction sequences, and the encoding against the interpreter on
//! every instruction of the fixtures that has semantics.
//!
//! Needs `z3` on the `PATH` (skipped with a notice otherwise).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::{Command, Stdio};

use binbun_semantics::Semantics;
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{self, Fault, Machine, Outcome, Value};
use binbun_semantics::ir::{Expr, RegisterId, Stmt};
use binbun_semantics::smt::{self, Final, Options, Script, State, Term};
use binbun_x86::{Mode, decode};
use binbun_x86_lift::registers::RAX;
use binbun_x86_lift::{X86, lift};

const CODE: u64 = 0x40_1000;

fn register(name: &str) -> RegisterId {
    X86.find(name).unwrap()
}

fn semantics(bytes: &[u8], address: u64) -> Semantics {
    let instruction = decode(bytes, Mode::Bits64).unwrap();
    lift(&instruction, Mode::Bits64, address).unwrap()
}

/// Runs z3 on `script`, one output line per answer; `None` (with a notice)
/// if z3 is not installed.
fn z3(script: &str) -> Option<Vec<String>> {
    let mut child = match Command::new("z3")
        .args(["-in", "-smt2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            eprintln!("skipped: cannot run z3 ({error})");
            return None;
        }
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    Some(
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect(),
    )
}

/// The final state of running `sequence` (instruction bytes, laid out from
/// [`CODE`]) from `initial`, and whether any instruction trapped or
/// transferred control (sequences here are straight-line code).
fn run(script: &mut Script, sequence: &[&[u8]], initial: &State, prefix: &str) -> Final {
    let options = Options::default();
    let mut address = CODE;
    let mut state = initial.clone();
    let mut stopped = Vec::new();
    let mut last = None;
    for (index, bytes) in sequence.iter().enumerate() {
        let semantics = semantics(bytes, address);
        let done = script
            .encode(
                &semantics,
                &X86,
                &state,
                &format!("{prefix}{index}."),
                &options,
            )
            .unwrap();
        stopped.push(done.trap.clone());
        stopped.push(done.transferred.clone());
        state = done.state.clone();
        address += bytes.len() as u64;
        last = Some(done);
    }
    let mut done = last.unwrap();
    done.trap = smt::or(&stopped);
    done.transferred = smt::bottom();
    done
}

/// Final state "nothing ran".
fn identity(initial: &State) -> Final {
    Final {
        state: initial.clone(),
        trap: smt::bottom(),
        traps: Vec::new(),
        transferred: smt::bottom(),
        target: smt::literal(64, 0),
        system_call: smt::bottom(),
        loads: Vec::new(),
        stores: Vec::new(),
        exhausted: smt::bottom(),
    }
}

/// Asks whether `claim` holds in every state: z3 answers `unsat` for its
/// negation.
fn prove(script: &mut Script, claim: &Term) {
    script.push();
    script.assert(&smt::not(claim));
    script.command("(check-sat)");
    script.pop();
}

#[test]
fn xor_eax_eax_zeroes_rax_and_sets_zf() {
    let mut script = Script::new();
    let initial = script.initial_state(&X86, "s.", &Options::default());
    let done = run(&mut script, &[&[0x31, 0xc0]], &initial, "xor");
    let rax = done.state.register(RAX).unwrap();
    let flag = |name| done.state.register(register(name)).unwrap();
    let claim = smt::and(&[
        smt::not(&done.trap),
        smt::eq(rax, &smt::literal(64, 0)),
        smt::eq(flag("zf"), &smt::literal(1, 1)),
        smt::eq(flag("cf"), &smt::literal(1, 0)),
        smt::eq(flag("of"), &smt::literal(1, 0)),
        smt::eq(flag("sf"), &smt::literal(1, 0)),
        smt::eq(flag("pf"), &smt::literal(1, 1)),
    ]);
    prove(&mut script, &claim);
    // Not a tautology of the encoding: `xor eax, ebx` does not do it.
    let other = run(&mut script, &[&[0x31, 0xd8]], &initial, "xor-ebx");
    let zero = smt::eq(other.state.register(RAX).unwrap(), &smt::literal(64, 0));
    prove(&mut script, &zero);
    let Some(answers) = z3(script.as_str()) else {
        return;
    };
    assert_eq!(answers, ["unsat", "sat"]);
}

#[test]
fn equivalent_sequences_are_proved_equal() {
    let mut script = Script::new();
    let initial = script.initial_state(&X86, "s.", &Options::default());
    let rip = [register("rip")];
    // xchg rax, rbx twice: nothing changes, registers, flags or memory.
    let twice = run(
        &mut script,
        &[&[0x48, 0x87, 0xd8], &[0x48, 0x87, 0xd8]],
        &initial,
        "x",
    );
    prove(
        &mut script,
        &smt::same_outcome(&twice, &identity(&initial), &rip),
    );
    // push rbx; pop rax: as mov rax, rbx (unless the push faults on a
    // non-canonical stack pointer), but for the stack slot written.
    let pushpop = run(&mut script, &[&[0x53], &[0x58]], &initial, "p");
    let mov = run(&mut script, &[&[0x48, 0x89, 0xd8]], &initial, "m");
    let registers_alike: Vec<Term> = (0..X86.registers.len())
        .map(|index| {
            let id = RegisterId(u16::try_from(index).unwrap());
            smt::eq(
                pushpop.state.register(id).unwrap(),
                mov.state.register(id).unwrap(),
            )
        })
        .collect();
    prove(
        &mut script,
        &smt::or(&[pushpop.trap, smt::and(&registers_alike)]),
    );
    // lea rax, [rbx + rbx*2] and imul rax, rbx, 3 compute the same rax.
    let lea = run(&mut script, &[&[0x48, 0x8d, 0x04, 0x5b]], &initial, "l");
    let imul = run(&mut script, &[&[0x48, 0x6b, 0xc3, 0x03]], &initial, "i");
    prove(
        &mut script,
        &smt::eq(
            lea.state.register(RAX).unwrap(),
            imul.state.register(RAX).unwrap(),
        ),
    );
    let Some(answers) = z3(script.as_str()) else {
        return;
    };
    assert_eq!(answers, ["unsat", "unsat", "unsat"]);
}

/// `add rax, 1` and `inc rax` agree on everything but the carry flag; the
/// solver's counterexample for the carry, replayed in the interpreter,
/// really gives different carries.
#[test]
fn add_one_and_inc_differ_in_the_carry_only() {
    let add: &[u8] = &[0x48, 0x83, 0xc0, 0x01];
    let inc: &[u8] = &[0x48, 0xff, 0xc0];
    let cf = register("cf");
    let mut script = Script::new();
    let initial = script.initial_state(&X86, "s.", &Options::default());
    let one = run(&mut script, &[add], &initial, "a");
    let other = run(&mut script, &[inc], &initial, "i");
    let rip = register("rip");
    prove(&mut script, &smt::same_outcome(&one, &other, &[cf, rip]));
    script.assert(&smt::not(&smt::same_outcome(&one, &other, &[rip])));
    script.command("(check-sat)");
    script.command("(get-value (|s.rax|))");
    script.command("(get-value (|s.cf|))");
    let Some(answers) = z3(script.as_str()) else {
        return;
    };
    assert_eq!(answers[..2], ["unsat", "sat"]);
    let value = |line: &str| {
        let literal = line.trim_end_matches(')').rsplit(' ').next().unwrap();
        smt::parse_literal(literal).unwrap()
    };
    let rax = value(&answers[2]);
    let carry = value(&answers[3]);
    let carry_after = |bytes: &[u8]| {
        let mut machine = Test::new(BTreeMap::from([
            (RAX.0, Value::defined(rax)),
            (cf.0, Value::defined(carry)),
        ]));
        assert_eq!(
            interpret::run(&semantics(bytes, CODE), &mut machine),
            Outcome::Next
        );
        machine.registers[&cf.0]
    };
    assert_ne!(
        carry_after(add),
        carry_after(inc),
        "rax {rax:?}, cf {carry:?}"
    );
}

/// Registers and sparse memory: bytes not yet stored are a function of the
/// address. Records the addresses accessed.
struct Test {
    registers: BTreeMap<u16, Value>,
    memory: BTreeMap<u64, u8>,
    touched: BTreeSet<u64>,
}

impl Test {
    fn new(registers: BTreeMap<u16, Value>) -> Self {
        Self {
            registers,
            memory: BTreeMap::new(),
            touched: BTreeSet::new(),
        }
    }

    fn byte(&mut self, address: u64) -> u8 {
        self.touched.insert(address);
        *self
            .memory
            .entry(address)
            .or_insert_with(|| initial_byte(address))
    }
}

fn initial_byte(address: u64) -> u8 {
    (address.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 56) as u8
}

impl Machine for Test {
    fn read(&mut self, register: RegisterId) -> Value {
        let width = X86.info(register).unwrap().width;
        self.registers
            .get(&register.0)
            .copied()
            .unwrap_or_else(|| Value::defined(Bits::zero(width)))
    }

    fn write(&mut self, register: RegisterId, value: Value) {
        self.registers.insert(register.0, value);
    }

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        let data: Vec<u8> = (0..u64::from(bytes))
            .map(|i| self.byte(address.wrapping_add(i)))
            .collect();
        Ok(Value::defined(Bits::from_le_bytes(bytes * 8, &data)))
    }

    fn store(&mut self, address: u64, value: Value) -> Result<(), Fault> {
        for (i, byte) in value.bits.to_le_bytes().enumerate() {
            let at = address.wrapping_add(i as u64);
            self.byte(at);
            self.memory.insert(at, byte);
        }
        Ok(())
    }
}

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bits(&mut self, width: u16) -> Bits {
        let bytes: Vec<u8> = (0..usize::from(width).div_ceil(8))
            .map(|_| match self.next() % 4 {
                0 => 0,
                1 => 0xff,
                _ => self.next().to_le_bytes()[0],
            })
            .collect();
        Bits::from_le_bytes(width, &bytes)
    }
}

fn has_float_or_loop(semantics: &Semantics) -> (bool, bool) {
    fn loops(body: &[Stmt]) -> bool {
        body.iter().any(|stmt| match stmt {
            Stmt::Loop(_) => true,
            Stmt::If {
                then, otherwise, ..
            } => loops(then) || loops(otherwise),
            Stmt::Atomic(body) => loops(body),
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
            | Stmt::Intrinsic { .. } => false,
        })
    }
    let float = semantics
        .exprs
        .iter()
        .any(|(expr, _)| matches!(expr, Expr::Float { .. }));
    (float, loops(&semantics.body))
}

/// Boolean: the encoding ends as the interpreter did, on the bits the
/// interpreter defines.
fn expectation(done: &Final, machine: &Test, outcome: Outcome) -> Option<Term> {
    let mut parts = vec![smt::not(&done.exhausted)];
    match outcome {
        Outcome::Trap(_) => {
            parts.push(done.trap.clone());
            return Some(smt::and(&parts));
        }
        Outcome::Next => parts.push(smt::not(&done.transferred)),
        Outcome::Transfer(target) => {
            parts.push(done.transferred.clone());
            parts.push(smt::eq(&done.target, &smt::literal(64, target)));
        }
        Outcome::SystemCall => parts.push(done.system_call.clone()),
        Outcome::Fault(_) | Outcome::Undetermined | Outcome::OutOfFuel => return None,
        Outcome::Malformed => panic!("malformed semantics"),
    }
    parts.push(smt::not(&done.trap));
    let defined = |term: &Term, value: &Value| {
        let mask = smt::constant(&value.undefined.invert());
        smt::eq(
            &Term::new(format!("(bvand {term} {mask})")),
            &smt::constant(&value.bits),
        )
    };
    for (index, value) in &machine.registers {
        let register = done.state.register(RegisterId(*index)).unwrap();
        parts.push(defined(register, value));
    }
    for (address, byte) in &machine.memory {
        let cell = Term::new(format!(
            "(select {} {})",
            done.state.memory,
            smt::literal(64, *address)
        ));
        parts.push(smt::eq(&cell, &smt::literal(8, u64::from(*byte))));
    }
    Some(smt::and(&parts))
}

/// Every fixture instruction with integer semantics (up to three per form),
/// from random states: z3 must prove the encoding ends as the interpreter
/// does.
#[test]
fn fixture_instructions_match_the_interpreter() {
    let mut random = Random(0x0123_4567_89ab_cdef);
    let mut per_form = BTreeMap::new();
    let mut script = Script::new();
    let mut cases = Vec::new();
    let fixtures = [
        "program-x86_64.elf",
        "exceptions-x86_64.elf",
        "program-x86_64.exe",
    ];
    let found = fixtures
        .iter()
        .flat_map(|name| support::sweep(&support::fixture(name)));
    for found in found {
        let Ok(semantics) = lift(&found.instruction, Mode::Bits64, found.address) else {
            continue;
        };
        let (float, looping) = has_float_or_loop(&semantics);
        let count = per_form.entry(found.instruction.form()).or_insert(0);
        if float || *count >= 4 {
            continue;
        }
        *count += 1;
        let mut values: BTreeMap<u16, Value> = X86
            .registers
            .iter()
            .enumerate()
            .map(|(index, info)| {
                (
                    u16::try_from(index).unwrap(),
                    Value::defined(random.bits(info.width)),
                )
            })
            .collect();
        if looping {
            // Small counts, so string loops end within the unrolling.
            let rcx = register("rcx").0;
            values.insert(rcx, Value::defined(Bits::from_u64(64, random.next() % 5)));
        }
        let mut machine = Test::new(values.clone());
        let outcome = interpret::run(&semantics, &mut machine);
        script.push();
        let options = Options {
            address_width: 64,
            unroll: 6,
        };
        let initial = script.initial_state(&X86, "s.", &options);
        let done = script
            .encode(&semantics, &X86, &initial, "e", &options)
            .unwrap();
        let Some(expected) = expectation(&done, &machine, outcome) else {
            script.pop();
            continue;
        };
        for (index, value) in &values {
            script.assert(&smt::eq(
                initial.register(RegisterId(*index)).unwrap(),
                &smt::constant(&value.bits),
            ));
        }
        for &address in &machine.touched {
            let cell = Term::new(format!(
                "(select {} {})",
                initial.memory,
                smt::literal(64, address)
            ));
            script.assert(&smt::eq(
                &cell,
                &smt::literal(8, u64::from(initial_byte(address))),
            ));
        }
        script.assert(&smt::not(&expected));
        script.command("(check-sat)");
        script.pop();
        cases.push(found.instruction.intel(found.address).to_string());
    }
    assert!(
        cases.len() > 100,
        "only {} instructions checked",
        cases.len()
    );
    let Some(answers) = z3(script.as_str()) else {
        return;
    };
    assert_eq!(answers.len(), cases.len(), "{answers:?}");
    let failures: Vec<&String> = cases
        .iter()
        .zip(&answers)
        .filter(|(_, answer)| answer.as_str() != "unsat")
        .map(|(case, _)| case)
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}
